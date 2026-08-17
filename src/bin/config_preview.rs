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
    let removal_action = desired
        .configuration
        .reconciliation
        .deletion_policy
        .as_str();
    diff(
        "clients",
        &active.configuration.clients,
        &desired.configuration.clients,
        |client| &client.id,
        removal_action,
        &mut operations,
    );
    diff(
        "issuers",
        &active.configuration.issuers,
        &desired.configuration.issuers,
        |issuer| &issuer.id,
        removal_action,
        &mut operations,
    );
    diff(
        "users",
        &active.configuration.users,
        &desired.configuration.users,
        |user| &user.id,
        removal_action,
        &mut operations,
    );
    diff_single(
        "branding",
        &active.configuration.branding,
        &desired.configuration.branding,
        &mut operations,
    );
    diff_single(
        "claims",
        &active.configuration.claims,
        &desired.configuration.claims,
        &mut operations,
    );
    diff_single(
        "authentication",
        &active.configuration.authentication,
        &desired.configuration.authentication,
        &mut operations,
    );
    diff_single(
        "reconciliation",
        &active.configuration.reconciliation,
        &desired.configuration.reconciliation,
        &mut operations,
    );
    diff_single(
        "storage",
        &active.configuration.storage,
        &desired.configuration.storage,
        &mut operations,
    );
    diff_single(
        "telemetry",
        &active.configuration.telemetry,
        &desired.configuration.telemetry,
        &mut operations,
    );
    operations.sort();
    let changes_required = operations
        .iter()
        .any(|(_, _, action)| action != "unchanged");

    println!("revision\t{}", desired.revision);
    println!("changes_required\t{changes_required}");
    println!("diagnostics\tnone");
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
    removal_action: &str,
    operations: &mut Vec<(String, String, String)>,
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
        operations.push((resource.to_owned(), item_id.clone(), action.to_owned()));
    }
    for item_id in active
        .keys()
        .filter(|item_id| !desired.contains_key(*item_id))
    {
        operations.push((
            resource.to_owned(),
            item_id.clone(),
            removal_action.to_owned(),
        ));
    }
}

fn diff_single<T: Serialize>(
    resource: &str,
    active: &T,
    desired: &T,
    operations: &mut Vec<(String, String, String)>,
) {
    let active = serde_json::to_value(active).unwrap_or(Value::Null);
    let desired = serde_json::to_value(desired).unwrap_or(Value::Null);
    let action = if active == desired {
        "unchanged"
    } else {
        "update"
    };
    operations.push((resource.to_owned(), "global".to_owned(), action.to_owned()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Resource {
        id: String,
        value: u8,
    }

    #[test]
    fn plans_configured_removal_action_and_global_updates() {
        let active = vec![Resource {
            id: "removed".to_owned(),
            value: 1,
        }];
        let desired = Vec::<Resource>::new();
        let mut operations = Vec::new();
        diff(
            "clients",
            &active,
            &desired,
            |resource| &resource.id,
            "delete",
            &mut operations,
        );
        diff_single("telemetry", &1_u8, &2_u8, &mut operations);

        assert!(operations.contains(&(
            "clients".to_owned(),
            "removed".to_owned(),
            "delete".to_owned()
        )));
        assert!(operations.contains(&(
            "telemetry".to_owned(),
            "global".to_owned(),
            "update".to_owned()
        )));
    }
}
