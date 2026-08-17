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
        |active, desired| {
            if active.enabled && !desired.enabled {
                "disable"
            } else {
                "update"
            }
        },
        &mut operations,
    );
    diff(
        "issuers",
        &active.configuration.issuers,
        &desired.configuration.issuers,
        |issuer| &issuer.id,
        removal_action,
        |active, desired| {
            if active.enabled && !desired.enabled {
                "disable"
            } else {
                "update"
            }
        },
        &mut operations,
    );
    diff(
        "users",
        &active.configuration.users,
        &desired.configuration.users,
        |user| &user.id,
        removal_action,
        |active, desired| {
            if active.enabled && !desired.enabled {
                "disable"
            } else {
                "update"
            }
        },
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
        "authorization_detail_types",
        &active.configuration.authorization_detail_types,
        &desired.configuration.authorization_detail_types,
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

fn diff<T, F, C>(
    resource: &str,
    active: &[T],
    desired: &[T],
    id: F,
    removal_action: &str,
    changed_action: C,
    operations: &mut Vec<(String, String, String)>,
) where
    T: Serialize,
    F: Fn(&T) -> &String,
    C: Fn(&T, &T) -> &'static str,
{
    let active = active
        .iter()
        .map(|item| (id(item).clone(), item))
        .collect::<BTreeMap<_, _>>();
    let desired = desired
        .iter()
        .map(|item| (id(item).clone(), item))
        .collect::<BTreeMap<_, _>>();

    for (item_id, desired_item) in &desired {
        let action = match active.get(item_id) {
            None => "create",
            Some(active_item)
                if serde_json::to_value(*active_item).unwrap_or(Value::Null)
                    == serde_json::to_value(*desired_item).unwrap_or(Value::Null) =>
            {
                "unchanged"
            }
            Some(active_item) => changed_action(active_item, desired_item),
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
        enabled: bool,
    }

    #[test]
    fn plans_configured_removal_action_and_global_updates() {
        let active = vec![Resource {
            id: "removed".to_owned(),
            value: 1,
            enabled: true,
        }];
        let desired = Vec::<Resource>::new();
        let mut operations = Vec::new();
        diff(
            "clients",
            &active,
            &desired,
            |resource| &resource.id,
            "delete",
            |active, desired| {
                if active.enabled && !desired.enabled {
                    "disable"
                } else {
                    "update"
                }
            },
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

    #[test]
    fn reports_explicit_suspension_as_disable_and_reactivation_as_update() {
        let active = vec![Resource {
            id: "application".to_owned(),
            value: 1,
            enabled: true,
        }];
        let suspended = vec![Resource {
            id: "application".to_owned(),
            value: 1,
            enabled: false,
        }];
        let mut operations = Vec::new();
        let changed_action = |active: &Resource, desired: &Resource| {
            if active.enabled && !desired.enabled {
                "disable"
            } else {
                "update"
            }
        };
        diff(
            "clients",
            &active,
            &suspended,
            |resource| &resource.id,
            "delete",
            changed_action,
            &mut operations,
        );
        assert_eq!(operations[0].2, "disable");

        operations.clear();
        diff(
            "clients",
            &suspended,
            &active,
            |resource| &resource.id,
            "delete",
            changed_action,
            &mut operations,
        );
        assert_eq!(operations[0].2, "update");
    }
}
