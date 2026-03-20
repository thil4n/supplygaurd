pub struct SimilarPackage {
    pub target: String,
    pub distance: usize,
}

/// Top npm packages by dependents — used as the typosquat reference list.
const POPULAR_PACKAGES: &[&str] = &[
    "lodash", "express", "react", "react-dom", "typescript",
    "axios", "moment", "commander", "chalk", "debug",
    "webpack", "eslint", "jest", "mocha", "prettier",
    "bluebird", "underscore", "request", "async", "uuid",
    "dotenv", "fs-extra", "mkdirp", "rimraf", "semver",
    "glob", "minimist", "yargs", "inquirer", "nodemon",
    "cross-env", "concurrently", "husky", "body-parser", "cors",
    "helmet", "morgan", "mongoose", "sequelize", "knex",
    "redis", "socket.io", "node-fetch", "got", "superagent",
    "cheerio", "puppeteer", "playwright", "esbuild", "vite",
    "rollup", "parcel", "babel-core", "core-js", "rxjs",
    "next", "nuxt", "gatsby", "svelte", "vue",
    "angular", "nestjs", "fastify", "koa", "hapi",
];

/// Flag names within this OSA distance of a popular package.
const MAX_DISTANCE: usize = 1;

pub fn find_similar(name: &str) -> Vec<SimilarPackage> {
    // Skip scoped packages and very short names to reduce false positives.
    if name.starts_with('@') || name.len() < 4 {
        return vec![];
    }
    POPULAR_PACKAGES
        .iter()
        .filter(|&&popular| popular != name)
        .filter_map(|&popular| {
            let d = osa_distance(name, popular);
            if d <= MAX_DISTANCE {
                Some(SimilarPackage { target: popular.to_string(), distance: d })
            } else {
                None
            }
        })
        .collect()
}

/// Optimal String Alignment distance — like Levenshtein but also handles
/// single transpositions (e.g. "lodahs" → "lodash" = 1, not 2).
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());

    // Fast exit: length difference alone exceeds threshold.
    if m.abs_diff(n) > MAX_DISTANCE {
        return MAX_DISTANCE + 1;
    }

    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)          // deletion
                .min(dp[i][j - 1] + 1)              // insertion
                .min(dp[i - 1][j - 1] + cost);      // substitution
            // Transposition
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + 1);
            }
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_not_flagged() {
        assert!(find_similar("lodash").is_empty());
    }

    #[test]
    fn test_transposition_typo_flagged() {
        // "lodahs" is "lodash" with the last two chars swapped — OSA distance 1
        let results = find_similar("lodahs");
        assert!(
            results.iter().any(|r| r.target == "lodash" && r.distance == 1),
            "lodahs should be flagged as a typosquat of lodash"
        );
    }

    #[test]
    fn test_substitution_typo_flagged() {
        let results = find_similar("lodXsh");
        assert!(results.iter().any(|r| r.target == "lodash"));
    }

    #[test]
    fn test_insertion_typo_flagged() {
        let results = find_similar("lodaash");
        assert!(results.iter().any(|r| r.target == "lodash"));
    }

    #[test]
    fn test_distance_two_not_flagged() {
        assert!(find_similar("loXaXh").is_empty());
    }

    #[test]
    fn test_short_name_ignored() {
        // Under 4 chars → skip regardless of similarity
        assert!(find_similar("koa").is_empty());
    }

    #[test]
    fn test_scoped_package_ignored() {
        assert!(find_similar("@types/lodash").is_empty());
    }

    #[test]
    fn test_unrelated_name_not_flagged() {
        assert!(find_similar("my-unique-library-xyz").is_empty());
    }

    #[test]
    fn test_osa_distance_zero_for_same() {
        assert_eq!(osa_distance("lodash", "lodash"), 0);
    }

    #[test]
    fn test_osa_distance_transposition() {
        assert_eq!(osa_distance("lodash", "lodahs"), 1);
    }

    #[test]
    fn test_osa_distance_substitution() {
        assert_eq!(osa_distance("lodash", "lodXsh"), 1);
    }

    #[test]
    fn test_osa_distance_deletion() {
        assert_eq!(osa_distance("lodash", "lodsh"), 1);
    }

    #[test]
    fn test_osa_distance_insertion() {
        assert_eq!(osa_distance("lodash", "lodaash"), 1);
    }
}
