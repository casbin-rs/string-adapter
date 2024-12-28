mod utils;
use async_trait::async_trait;
use casbin::{
    error::{AdapterError, ModelError},
    Adapter, Filter, Model, Result,
};
use std::fmt::Write;
use utils::*;

#[derive(Default)]
pub struct StringAdapter {
    policy: String,
    is_filtered: bool,
}

impl StringAdapter {
    pub fn new(s: impl ToString) -> Self {
        Self {
            policy: s.to_string(),
            is_filtered: false,
        }
    }
}

#[async_trait]
impl Adapter for StringAdapter {
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let policies = self.policy.split("\n");
        for line in policies {
            load_policy_line(line, m);
        }
        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        let policies = self.policy.split("\n");
        for line in policies {
            if let Some(tokens) = parse_csv_line(line) {
                let sec = &tokens[0];
                let ptype = &tokens[1];
                let rule = tokens[1..].to_vec().clone();
                let mut is_filtered = false;

                if sec == "p" {
                    for (i, r) in f.p.iter().enumerate() {
                        if !r.is_empty() && r != &rule[i + 1] {
                            is_filtered = true;
                        }
                    }
                }
                if sec == "g" {
                    for (i, r) in f.g.iter().enumerate() {
                        if !r.is_empty() && r != &rule[i + 1] {
                            is_filtered = true;
                        }
                    }
                }
                if !is_filtered {
                    if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                        if let Some(ast) = ast_map.get_mut(ptype) {
                            ast.get_mut_policy().insert(rule);
                        }
                    }
                } else {
                    self.is_filtered = true;
                }
            }
        }
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut policies = String::new();
        let ast_map = m
            .get_model()
            .get("p")
            .ok_or_else(|| ModelError::P("Missing policy definition in conf file".to_owned()))?;

        for (ptype, ast) in ast_map {
            for rule in ast.get_policy() {
                writeln!(policies, "{}, {}", ptype, rule.join(", "))
                    .map_err(|e| AdapterError(e.into()))?;
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                for rule in ast.get_policy() {
                    writeln!(policies, "{}, {}", ptype, rule.join(", "))
                        .map_err(|e| AdapterError(e.into()))?;
                }
            }
        }

        self.policy = policies;
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.policy.clear();
        self.is_filtered = false;
        Ok(())
    }

    async fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<String>) -> Result<bool> {
        // not implemented
        Err(casbin::Error::AdapterError(AdapterError(
            "not implemented".to_string().into(),
        )))
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        // not implemented
        Err(casbin::Error::AdapterError(AdapterError(
            "not implemented".to_string().into(),
        )))
    }

    async fn remove_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<String>,
    ) -> Result<bool> {
        // not implemented
        Err(casbin::Error::AdapterError(AdapterError(
            "not implemented".to_string().into(),
        )))
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _rule: Vec<Vec<String>>,
    ) -> Result<bool> {
        // not implemented
        Err(casbin::Error::AdapterError(AdapterError(
            "not implemented".to_string().into(),
        )))
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<String>,
    ) -> Result<bool> {
        // not implemented
        Err(casbin::Error::AdapterError(AdapterError(
            "not implemented".to_string().into(),
        )))
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}

#[cfg(test)]
mod tests {
    use crate::StringAdapter;
    use casbin::{Adapter, CoreApi, Filter};
    use casbin::{DefaultModel, Enforcer};

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_load_policy() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = StringAdapter::new(policy);
        let mut model = DefaultModel::from_str(
            "[request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [role_definition]
            g = _, _

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && r.obj == p.obj && r.act == p.act",
        )
        .await
        .unwrap();

        adapter.load_policy(&mut model).await.unwrap();
        let enforcer = Enforcer::new(model, adapter).await.unwrap();

        assert!(enforcer.enforce(("alice", "data1", "read")).unwrap());
        assert!(enforcer.enforce(("bob", "data2", "write")).unwrap());
        assert!(!enforcer.enforce(("alice", "data2", "read")).unwrap());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_save_policy() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = StringAdapter::new(policy);
        let mut model = DefaultModel::from_str(
            "[request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [role_definition]
            g = _, _

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && r.obj == p.obj && r.act == p.act",
        )
        .await
        .unwrap();

        adapter.load_policy(&mut model).await.unwrap();
        adapter.save_policy(&mut model).await.unwrap();

        assert_eq!(
            adapter.policy,
            "p, alice, data1, read\np, bob, data2, write\n"
        );
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_clear_policy() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = StringAdapter::new(policy);
        let mut model = DefaultModel::from_str(
            "[request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [role_definition]
            g = _, _

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && r.obj == p.obj && r.act == p.act",
        )
        .await
        .unwrap();

        adapter.load_policy(&mut model).await.unwrap();
        adapter.clear_policy().await.unwrap();

        assert_eq!(adapter.policy, "");
        assert!(!adapter.is_filtered);
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_is_filtered() {
        let policy = "p, alice, data1, read\np, bob, data2, write";
        let mut adapter = StringAdapter::new(policy);
        let mut model = DefaultModel::from_str(
            "[request_definition]
            r = sub, obj, act

            [policy_definition]
            p = sub, obj, act

            [role_definition]
            g = _, _

            [policy_effect]
            e = some(where (p.eft == allow))

            [matchers]
            m = r.sub == p.sub && r.obj == p.obj && r.act == p.act",
        )
        .await
        .unwrap();

        let filter = Filter {
            p: vec!["alice"],
            g: vec![],
        };

        adapter
            .load_filtered_policy(&mut model, filter)
            .await
            .unwrap();
        assert!(adapter.is_filtered());
    }
}