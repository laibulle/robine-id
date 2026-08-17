use robine_id::Snapshot;
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, env, io, path::Path};

fn main() -> io::Result<()> {
    let active = Snapshot::load().map_err(io::Error::other)?;
    let desired = match env::args().nth(1) {
        Some(path) => Snapshot::load_path(Path::new(&path)).map_err(io::Error::other)?,
        None => active.clone(),
    };

    let mut operations = Vec::new();
    diff(
        "clients",
        &active.configuration.clients,
        &desired.configuration.clients,
        |client| &client.id,
        &mut operations,
    );
    diff(
        "issuers",
        &active.configuration.issuers,
        &desired.configuration.issuers,
        |issuer| &issuer.id,
        &mut operations,
    );
    diff(
        "users",
        &active.configuration.users,
        &desired.configuration.users,
        |user| &user.id,
        &mut operations,
    );
    operations.sort();

    println!("revision\t{}", desired.revision);
    for (resource, id, action) in operations {
        println!("{action}\t{resource}\t{id}");
    }
    Ok(())
}

fn diff<T, F>(
    resource: &str,
    active: &[T],
    desired: &[T],
    id: F,
    operations: &mut Vec<(String, String, &'static str)>,
) where
    T: Serialize,
    F: Fn(&T) -> &String,
{
    let index = |items: &[T]| {
        items
            .iter()
            .map(|item| {
                (
                    id(item).clone(),
                    serde_json::to_value(item).unwrap_or(Value::Null),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let active = index(active);
    let desired = index(desired);

    for (item_id, value) in &desired {
        let action = match active.get(item_id) {
            None => "create",
            Some(active) if active == value => "unchanged",
            Some(_) => "update",
        };
        operations.push((resource.to_owned(), item_id.clone(), action));
    }
    for item_id in active
        .keys()
        .filter(|item_id| !desired.contains_key(*item_id))
    {
        operations.push((resource.to_owned(), item_id.clone(), "disable"));
    }
}
