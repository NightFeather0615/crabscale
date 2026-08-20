//! Tag ownership validation against the policy's `tagOwners`.
//!
//! [Spec-Policy §4](https://github.com/NightFeather0615/crabscale/wiki/Spec-Policy.md)
//! describes the tag approval rules:
//!
//! - Tag names start with `tag:`.
//! - Only principals listed in `tagOwners[tag]` may approve that tag.
//! - Tag ownership may be delegated through groups (`group:eng`) and
//!   through other tags (`tag:ci` may mint `tag:prod` when the policy
//!   declares `"tag:prod": ["tag:ci"]`).
//!
//! These helpers answer "is this tag approvable by this user?" and are used
//! both to reject unauthorized pre-auth keys and to authorize `RequestTags`
//! transitions. Control-plane decisions live in `crabscale-control`; this
//! module only evaluates the policy.

use std::collections::BTreeSet;

use crate::model::Policy;

/// Whether `tag` is a structurally valid tag name (`tag:` plus a non-empty
/// suffix made of ASCII letters, digits, and dashes).
///
/// Validation is intentionally structural: ownership is a separate question
/// answered by [`user_can_use_tag`] and [`tag_owned_by_tags`].
pub fn is_valid_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix("tag:") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Whether `principal` (one entry of a `tagOwners` value) designates
/// `user_login`.
///
/// A principal may be:
/// - the user's own login (`alice@example.com`);
/// - a group (`group:eng`) whose member list contains the user's login;
/// - a tag (`tag:ci`). A user cannot act through a tag directly, so a
///   bare tag principal only matches via [`tag_owned_by_tags`]; it matches
///   here only when the user login equals the tag (impossible) and is
///   therefore `false`.
///
/// Group references are resolved transitively.
fn principal_matches_user(policy: &Policy, principal: &str, user_login: &str) -> bool {
    if principal == user_login {
        return true;
    }
    if let Some(group) = principal.strip_prefix("group:") {
        if let Some(members) = policy.groups.get(group) {
            if members.iter().any(|m| {
                // Members may themselves be users or groups; resolve either.
                m != principal && principal_matches_user(policy, m, user_login)
            }) {
                return true;
            }
        }
    }
    false
}

/// Whether `user_login` may approve `tag` per the policy's `tagOwners`.
///
/// The user must be listed directly, or as a member of a listed group.
/// An undefined tag (absent from `tagOwners`) can never be approved.
pub fn user_can_use_tag(policy: &Policy, tag: &str, user_login: &str) -> bool {
    if !is_valid_tag(tag) {
        return false;
    }
    let Some(owners) = policy.tag_owners.get(tag) else {
        return false;
    };
    owners
        .iter()
        .any(|owner| principal_matches_user(policy, owner, user_login))
}

/// Whether a credential holding `owner_tags` may approve `tag`.
///
/// This is the tag-to-tag ownership half of approval: it reports `true`
/// when `tag` is one of `owner_tags`, or when `tag`'s `tagOwners` chain
/// transitively includes one of `owner_tags`. It is useful when a tagged
/// credential (for example a tagged pre-auth key or an operator service)
/// mints keys carrying further tags.
pub fn tag_owned_by_tags(policy: &Policy, tag: &str, owner_tags: &[String]) -> bool {
    if owner_tags.iter().any(|t| t == tag) {
        return true;
    }
    if !is_valid_tag(tag) {
        return false;
    }
    let mut visited = BTreeSet::new();
    fn walk(
        policy: &Policy,
        tag: &str,
        owner_tags: &[String],
        visited: &mut BTreeSet<String>,
    ) -> bool {
        if !visited.insert(tag.to_string()) {
            return false;
        }
        let Some(owners) = policy.tag_owners.get(tag) else {
            return false;
        };
        for owner in owners {
            if owner_tags.iter().any(|t| t == owner) {
                return true;
            }
            if owner.starts_with("tag:") && walk(policy, owner, owner_tags, visited) {
                return true;
            }
        }
        false
    }
    walk(policy, tag, owner_tags, &mut visited)
}

/// Return the subset of `requested` tags that `user_login` is not allowed
/// to use. An empty result means every requested tag is authorized.
///
/// An absent user login (`None`) cannot authorize any tag, so every
/// requested tag is returned as rejected.
pub fn unauthorized_tags(
    policy: &Policy,
    user_login: Option<&str>,
    requested: &[String],
) -> Vec<String> {
    let Some(user_login) = user_login else {
        return requested.to_vec();
    };
    requested
        .iter()
        .filter(|tag| !user_can_use_tag(policy, tag, user_login))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_policy;

    fn policy(text: &str) -> Policy {
        parse_policy(text).expect("policy must parse")
    }

    const TAG_OWNERS: &str = r#"
        "tagOwners": {
            "tag:web": ["alice@example.com", "group:ops"],
            "tag:prod": ["tag:ci"],
            "tag:ci": ["carol@example.com"]
        },
        "groups": { "ops": ["bob@example.com", "dave@example.com"] }
    "#;

    #[test]
    fn valid_tag_names() {
        assert!(is_valid_tag("tag:server"));
        assert!(is_valid_tag("tag:disk-1"));
        assert!(!is_valid_tag("server"));
        assert!(!is_valid_tag("tag:"));
        assert!(!is_valid_tag("tag:bad tag"));
    }

    #[test]
    fn user_directly_owns_tag() {
        let p = policy(&format!("{{{TAG_OWNERS}}}"));
        assert!(user_can_use_tag(&p, "tag:web", "alice@example.com"));
        assert!(!user_can_use_tag(&p, "tag:web", "eve@example.com"));
    }

    #[test]
    fn user_owns_tag_through_group() {
        let p = policy(&format!("{{{TAG_OWNERS}}}"));
        assert!(user_can_use_tag(&p, "tag:web", "bob@example.com"));
        assert!(user_can_use_tag(&p, "tag:web", "dave@example.com"));
        assert!(!user_can_use_tag(&p, "tag:web", "carol@example.com"));
    }

    #[test]
    fn undefined_tag_never_approved() {
        let p = policy(&format!("{{{TAG_OWNERS}}}"));
        assert!(!user_can_use_tag(&p, "tag:missing", "alice@example.com"));
    }

    #[test]
    fn tag_owned_by_tags_follows_chain() {
        let p = policy(&format!("{{{TAG_OWNERS}}}"));
        // carol owns tag:ci which owns tag:prod.
        assert!(tag_owned_by_tags(&p, "tag:ci", &["tag:ci".to_string()]));
        assert!(tag_owned_by_tags(&p, "tag:prod", &["tag:ci".to_string()]));
        // No chain connects tag:web to tag:ci, so it is not owned.
        assert!(!tag_owned_by_tags(&p, "tag:web", &["tag:ci".to_string()]));
        // A credential may always apply a tag it directly holds.
        assert!(tag_owned_by_tags(&p, "tag:prod", &["tag:prod".to_string()]));
    }

    #[test]
    fn unauthorized_tags_reports_only_rejected() {
        let p = policy(&format!("{{{TAG_OWNERS}}}"));
        let rejected = unauthorized_tags(
            &p,
            Some("alice@example.com"),
            &[
                "tag:web".to_string(),
                "tag:prod".to_string(),
                "tag:web".to_string(),
            ],
        );
        assert_eq!(rejected, vec!["tag:prod".to_string()]);
        assert!(unauthorized_tags(&p, Some("alice@example.com"), &[]).is_empty());
        // A user with no known login cannot authorize anything.
        assert_eq!(
            unauthorized_tags(&p, None, &["tag:web".to_string()]),
            vec!["tag:web".to_string()]
        );
    }
}
