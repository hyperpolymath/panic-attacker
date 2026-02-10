// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core relational logic engine
//!
//! A miniKanren-inspired engine using substitution-based unification
//! and forward/backward chaining for deriving vulnerability facts.

use crate::types::*;
use std::collections::{HashMap, HashSet};

/// A logic term in the fact database
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Term {
    /// Logic variable (unbound)
    Var(u32),
    /// String atom
    Atom(String),
    /// Integer value
    Int(i64),
    /// Compound term: functor(args...)
    Compound(String, Vec<Term>),
}

impl Term {
    pub fn atom(s: &str) -> Self {
        Term::Atom(s.to_string())
    }

    pub fn compound(name: &str, args: Vec<Term>) -> Self {
        Term::Compound(name.to_string(), args)
    }

    #[cfg(test)]
    pub fn is_var(&self) -> bool {
        matches!(self, Term::Var(_))
    }
}

/// Substitution: mapping from variable IDs to terms
#[derive(Debug, Clone, Default)]
pub struct Substitution {
    bindings: HashMap<u32, Term>,
}

impl Substitution {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk a term through the substitution, resolving variables
    pub fn walk(&self, term: &Term) -> Term {
        match term {
            Term::Var(id) => {
                if let Some(bound) = self.bindings.get(id) {
                    self.walk(bound)
                } else {
                    term.clone()
                }
            }
            _ => term.clone(),
        }
    }

    /// Unify two terms, extending the substitution if successful
    pub fn unify(&self, t1: &Term, t2: &Term) -> Option<Substitution> {
        let t1 = self.walk(t1);
        let t2 = self.walk(t2);

        match (&t1, &t2) {
            // Same term
            (a, b) if a == b => Some(self.clone()),

            // Variable binding
            (Term::Var(id), _) => {
                let mut new_subst = self.clone();
                new_subst.bindings.insert(*id, t2);
                Some(new_subst)
            }
            (_, Term::Var(id)) => {
                let mut new_subst = self.clone();
                new_subst.bindings.insert(*id, t1);
                Some(new_subst)
            }

            // Compound term unification
            (Term::Compound(f1, args1), Term::Compound(f2, args2)) => {
                if f1 != f2 || args1.len() != args2.len() {
                    return None;
                }
                let mut subst = self.clone();
                for (a1, a2) in args1.iter().zip(args2.iter()) {
                    subst = subst.unify(a1, a2)?;
                }
                Some(subst)
            }

            // No unification possible
            _ => None,
        }
    }

    /// Extract the resolved value of a variable
    #[cfg(test)]
    pub fn resolve(&self, var_id: u32) -> Option<Term> {
        let term = Term::Var(var_id);
        let resolved = self.walk(&term);
        if resolved.is_var() {
            None
        } else {
            Some(resolved)
        }
    }
}

/// A fact in the database (ground term - no variables)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicFact {
    pub relation: String,
    pub args: Vec<Term>,
}

impl LogicFact {
    pub fn new(relation: &str, args: Vec<Term>) -> Self {
        Self {
            relation: relation.to_string(),
            args,
        }
    }

    /// Convert to a compound term for unification
    pub fn to_term(&self) -> Term {
        Term::compound(&self.relation, self.args.clone())
    }
}

/// Metadata for inference rules
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub confidence: f64,
    pub priority: u32,
    pub tags: Vec<String>,
    pub risk_tier: Option<String>,
}

impl RuleMetadata {
    #[allow(dead_code)]
    pub fn new(
        confidence: f64,
        priority: u32,
        tags: Vec<String>,
        risk_tier: Option<String>,
    ) -> Self {
        Self {
            confidence,
            priority,
            tags,
            risk_tier,
        }
    }
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self {
            confidence: 0.5,
            priority: 0,
            tags: Vec::new(),
            risk_tier: None,
        }
    }
}

/// A rule: head :- body (if all body facts hold, derive head)
#[derive(Debug, Clone)]
pub struct LogicRule {
    pub name: String,
    pub head: LogicFact,
    pub body: Vec<LogicFact>,
    pub metadata: RuleMetadata,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleApplication {
    pub name: String,
    pub confidence: f64,
    pub priority: u32,
    pub tags: Vec<String>,
    pub risk_tier: Option<String>,
    pub derived: usize,
}

impl LogicRule {
    pub fn with_metadata(
        name: String,
        head: LogicFact,
        body: Vec<LogicFact>,
        metadata: RuleMetadata,
    ) -> Self {
        Self {
            name,
            head,
            body,
            metadata,
        }
    }
}

/// The fact database with forward chaining
#[derive(Debug, Default)]
pub struct FactDB {
    facts: HashSet<LogicFact>,
    rules: Vec<LogicRule>,
}

impl FactDB {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assert a new fact
    pub fn assert_fact(&mut self, fact: LogicFact) {
        self.facts.insert(fact);
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: LogicRule) {
        self.rules.push(rule);
    }

    /// Assert a convenience fact from relation name and string args
    #[cfg(test)]
    pub fn assert(&mut self, relation: &str, args: Vec<&str>) {
        self.assert_fact(LogicFact::new(
            relation,
            args.into_iter().map(Term::atom).collect(),
        ));
    }

    /// Query the database: find all substitutions matching a pattern
    #[cfg(test)]
    pub fn query(&self, relation: &str, pattern: &[Term]) -> Vec<Substitution> {
        let query_term = Term::Compound(relation.to_string(), pattern.to_vec());
        let mut results = Vec::new();

        for fact in &self.facts {
            if fact.relation != relation || fact.args.len() != pattern.len() {
                continue;
            }
            let subst = Substitution::new();
            if let Some(unified) = subst.unify(&query_term, &fact.to_term()) {
                results.push(unified);
            }
        }

        results
    }

    /// Forward chaining: apply all rules to derive new facts
    /// Returns the number of new facts derived plus rule applications
    pub fn forward_chain(&mut self) -> (usize, Vec<RuleApplication>) {
        let mut new_facts = Vec::new();
        let mut total_derived = 0;
        let mut applications = Vec::new();

        loop {
            new_facts.clear();

            for rule in &self.rules {
                // Try to match all body facts
                let matches = self.match_body(&rule.body);
                let mut derived_this_rule = 0;

                for subst in matches {
                    let derived = self.apply_substitution_to_fact(&rule.head, &subst);
                    if !self.facts.contains(&derived) {
                        new_facts.push(derived);
                        derived_this_rule += 1;
                    }
                }

                if derived_this_rule > 0 {
                    applications.push(RuleApplication {
                        name: rule.name.clone(),
                        confidence: rule.metadata.confidence,
                        priority: rule.metadata.priority,
                        tags: rule.metadata.tags.clone(),
                        risk_tier: rule.metadata.risk_tier.clone(),
                        derived: derived_this_rule,
                    });
                }
            }

            if new_facts.is_empty() {
                break;
            }

            total_derived += new_facts.len();
            for fact in new_facts.drain(..) {
                self.facts.insert(fact);
            }
        }

        (total_derived, applications)
    }

    /// Match a conjunction of body facts against the database
    fn match_body(&self, body: &[LogicFact]) -> Vec<Substitution> {
        if body.is_empty() {
            return vec![Substitution::new()];
        }

        let mut current_substs = vec![Substitution::new()];

        for body_fact in body {
            let mut next_substs = Vec::new();

            for subst in &current_substs {
                // Apply current substitution to body fact
                let resolved_fact = self.apply_substitution_to_fact(body_fact, subst);

                // Find matching database facts
                for db_fact in &self.facts {
                    if db_fact.relation != resolved_fact.relation
                        || db_fact.args.len() != resolved_fact.args.len()
                    {
                        continue;
                    }

                    let query = resolved_fact.to_term();
                    let target = db_fact.to_term();

                    if let Some(unified) = subst.unify(&query, &target) {
                        next_substs.push(unified);
                    }
                }
            }

            current_substs = next_substs;
            if current_substs.is_empty() {
                break;
            }
        }

        current_substs
    }

    /// Apply a substitution to a fact template
    fn apply_substitution_to_fact(&self, fact: &LogicFact, subst: &Substitution) -> LogicFact {
        LogicFact {
            relation: fact.relation.clone(),
            args: fact.args.iter().map(|arg| subst.walk(arg)).collect(),
        }
    }

    /// Count facts by relation
    #[cfg(test)]
    pub fn fact_count(&self, relation: &str) -> usize {
        self.facts.iter().filter(|f| f.relation == relation).count()
    }

    /// Get all facts for a relation
    pub fn get_facts(&self, relation: &str) -> Vec<&LogicFact> {
        self.facts
            .iter()
            .filter(|f| f.relation == relation)
            .collect()
    }

    /// Total fact count
    pub fn total_facts(&self) -> usize {
        self.facts.len()
    }

    /// Total rule count
    #[cfg(test)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// The main logic engine combining FactDB with inference
pub struct LogicEngine {
    pub db: FactDB,
}

impl LogicEngine {
    pub fn new() -> Self {
        Self { db: FactDB::new() }
    }

    /// Extract facts from an Assail report
    pub fn ingest_report(&mut self, report: &AssailReport) {
        // Assert language fact
        self.db.assert_fact(LogicFact::new(
            "language",
            vec![Term::atom(&format!("{:?}", report.language))],
        ));

        // Assert framework facts
        for fw in &report.frameworks {
            self.db.assert_fact(LogicFact::new(
                "framework",
                vec![Term::atom(&format!("{:?}", fw))],
            ));
        }

        // Assert weak point facts
        for wp in &report.weak_points {
            let loc = wp.location.as_deref().unwrap_or("unknown");
            self.db.assert_fact(LogicFact::new(
                "weak_point",
                vec![
                    Term::atom(&format!("{:?}", wp.category)),
                    Term::atom(loc),
                    Term::atom(&format!("{:?}", wp.severity)),
                ],
            ));
        }

        // Assert file statistics
        for fs in &report.file_statistics {
            self.db.assert_fact(LogicFact::new(
                "file_risk",
                vec![
                    Term::atom(&fs.file_path),
                    Term::Int(
                        (fs.unsafe_blocks * 3
                            + fs.panic_sites * 2
                            + fs.unwrap_calls
                            + fs.threading_constructs * 2) as i64,
                    ),
                ],
            ));
        }
    }

    /// Load standard vulnerability rules
    pub fn load_standard_rules(&mut self) {
        // Rule: tainted_path(Source, Sink) :-
        //   taint_source(File, Source),
        //   data_flow(File, File2),
        //   taint_sink(File2, Sink).
        let v0 = Term::Var(100);
        let v1 = Term::Var(101);
        let v2 = Term::Var(102);
        let v3 = Term::Var(103);

        self.db.add_rule(LogicRule::with_metadata(
            "tainted_path".into(),
            LogicFact::new(
                "tainted_path",
                vec![v0.clone(), v1.clone(), v2.clone(), v3.clone()],
            ),
            vec![
                LogicFact::new("taint_source", vec![v0.clone(), v1.clone()]),
                LogicFact::new("data_flow", vec![v0.clone(), v2.clone()]),
                LogicFact::new("taint_sink", vec![v2.clone(), v3.clone()]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: vulnerability_chain(File, Category) :-
        //   weak_point(Category, File, Severity),
        //   Severity = "Critical" | "High"
        let v4 = Term::Var(104);
        let v5 = Term::Var(105);
        self.db.add_rule(LogicRule::with_metadata(
            "critical_vuln".into(),
            LogicFact::new("critical_vuln", vec![v4.clone(), v5.clone()]),
            vec![LogicFact::new(
                "weak_point",
                vec![v4.clone(), v5.clone(), Term::atom("Critical")],
            )],
            RuleMetadata::default(),
        ));

        self.db.add_rule(LogicRule::with_metadata(
            "high_vuln".into(),
            LogicFact::new("high_vuln", vec![v4.clone(), v5.clone()]),
            vec![LogicFact::new(
                "weak_point",
                vec![v4.clone(), v5.clone(), Term::atom("High")],
            )],
            RuleMetadata::default(),
        ));

        // Rule: cross_lang_vuln(CallerFile, CalleeFile, Mechanism) :-
        //   cross_lang_call(CallerFile, CalleeFile, Mechanism),
        //   taint_source(CallerFile, _),
        //   taint_sink(CalleeFile, _).
        let v6 = Term::Var(106);
        let v7 = Term::Var(107);
        let v8 = Term::Var(108);
        let v9 = Term::Var(109);
        let v10 = Term::Var(110);

        self.db.add_rule(LogicRule::with_metadata(
            "cross_lang_vuln".into(),
            LogicFact::new("cross_lang_vuln", vec![v6.clone(), v7.clone(), v8.clone()]),
            vec![
                LogicFact::new("cross_lang_call", vec![v6.clone(), v7.clone(), v8.clone()]),
                LogicFact::new("taint_source", vec![v6.clone(), v9]),
                LogicFact::new("taint_sink", vec![v7.clone(), v10]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: excessive_risk(File) :-
        //   file_risk(File, Score),
        //   Score > 10
        // (Implemented as post-query filter since we don't have arithmetic in rules)
    }

    /// Run forward chaining and collect results
    pub fn analyze(&mut self) -> EngineResults {
        self.load_standard_rules();
        let (derived, _) = self.db.forward_chain();

        let tainted_paths = self.db.get_facts("tainted_path").len();
        let critical_vulns = self.db.get_facts("critical_vuln").len();
        let high_vulns = self.db.get_facts("high_vuln").len();
        let cross_lang = self.db.get_facts("cross_lang_vuln").len();

        EngineResults {
            total_facts: self.db.total_facts(),
            derived_facts: derived,
            tainted_paths,
            critical_vulnerabilities: critical_vulns,
            high_vulnerabilities: high_vulns,
            cross_language_vulns: cross_lang,
        }
    }
}

/// Results from the logic engine analysis
#[derive(Debug, Clone)]
pub struct EngineResults {
    pub total_facts: usize,
    pub derived_facts: usize,
    pub tainted_paths: usize,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub cross_language_vulns: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unification_atoms() {
        let subst = Substitution::new();
        let t1 = Term::atom("hello");
        let t2 = Term::atom("hello");
        assert!(subst.unify(&t1, &t2).is_some());

        let t3 = Term::atom("world");
        assert!(subst.unify(&t1, &t3).is_none());
    }

    #[test]
    fn test_unification_variables() {
        let subst = Substitution::new();
        let var = Term::Var(0);
        let atom = Term::atom("test");
        let result = subst.unify(&var, &atom).unwrap();
        assert_eq!(result.resolve(0), Some(Term::atom("test")));
    }

    #[test]
    fn test_compound_unification() {
        let subst = Substitution::new();
        let t1 = Term::compound("f", vec![Term::Var(0), Term::atom("b")]);
        let t2 = Term::compound("f", vec![Term::atom("a"), Term::atom("b")]);
        let result = subst.unify(&t1, &t2).unwrap();
        assert_eq!(result.resolve(0), Some(Term::atom("a")));
    }

    #[test]
    fn test_fact_query() {
        let mut db = FactDB::new();
        db.assert("parent", vec!["tom", "bob"]);
        db.assert("parent", vec!["tom", "liz"]);
        db.assert("parent", vec!["bob", "ann"]);

        let results = db.query("parent", &[Term::atom("tom"), Term::Var(0)]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_forward_chaining() {
        let mut db = FactDB::new();
        db.assert("parent", vec!["tom", "bob"]);
        db.assert("parent", vec!["bob", "ann"]);

        // Rule: grandparent(X, Z) :- parent(X, Y), parent(Y, Z)
        db.add_rule(LogicRule::with_metadata(
            "grandparent".into(),
            LogicFact::new("grandparent", vec![Term::Var(0), Term::Var(2)]),
            vec![
                LogicFact::new("parent", vec![Term::Var(0), Term::Var(1)]),
                LogicFact::new("parent", vec![Term::Var(1), Term::Var(2)]),
            ],
            RuleMetadata::default(),
        ));

        let (derived, _) = db.forward_chain();
        assert!(derived > 0);
        assert_eq!(db.fact_count("grandparent"), 1);
    }
}
