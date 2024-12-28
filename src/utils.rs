// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use casbin::Model;

use once_cell::sync::Lazy;
use regex::Regex;
static ESC_C: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(\s*"[^"]*"?|\s*[^,]*)"#).unwrap());

pub fn load_policy_line(line: &str, m: &mut dyn Model) {
    if line.is_empty() || line.starts_with('#') {
        return;
    }

    if let Some(tokens) = parse_csv_line(line) {
        let key = &tokens[0];

        if let Some(ref sec) = key.chars().next().map(|x| x.to_string()) {
            if let Some(ast_map) = m.get_mut_model().get_mut(sec) {
                if let Some(ast) = ast_map.get_mut(key) {
                    ast.policy.insert(tokens[1..].to_vec());
                }
            }
        }
    }
}

pub fn parse_csv_line<S: AsRef<str>>(line: S) -> Option<Vec<String>> {
    let line = line.as_ref().trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut res = vec![];
    for col in ESC_C.find_iter(line).map(|m| m.as_str().trim()) {
        res.push({
            if col.len() >= 2 && col.starts_with('"') && col.ends_with('"') {
                col[1..col.len() - 1].to_owned()
            } else {
                col.to_owned()
            }
        })
    }
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}
