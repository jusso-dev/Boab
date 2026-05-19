//! Pure scoring engine for the ASD LATICE rubric. No I/O.

use time::OffsetDateTime;

use crate::model::asset::{AssetType, CryptoAsset, MigrationDifficulty, PqcStatus};
use crate::model::score::RiskScore;
use crate::model::system::{Classification, Criticality, System};

const ALGO_UNKNOWN_DEFAULT: u8 = 7;
const HNDL_NO_HORIZON_DEFAULT: u8 = 5;

/// Normalise an algorithm string for class matching.
fn normalise_algorithm(name: &str) -> String {
    name.to_ascii_lowercase()
        .replace([' ', '_', '/'], "-")
        .replace("--", "-")
}

/// Returns the algorithm vulnerability score, 0 (PQC ready) to 10 (broken).
pub fn algo_vuln_score(asset: &CryptoAsset) -> u8 {
    if matches!(asset.pqc_status, PqcStatus::Hybrid) {
        return 5;
    }
    if matches!(asset.pqc_status, PqcStatus::Resistant) {
        return 1;
    }
    if matches!(asset.pqc_status, PqcStatus::SymmetricOk) {
        return 0;
    }

    let algo = normalise_algorithm(&asset.algorithm_name);
    let key_bits = key_size_bits(asset);

    // Broken or sub-broken classical primitives.
    if algo.contains("md5")
        || algo.contains("md4")
        || algo.contains("md2")
        || algo.contains("sha-0")
        || algo.contains("sha0")
        || algo == "sha1"
        || algo.contains("sha-1")
        || (algo.contains("rsa") && key_bits == Some(1024))
        || (algo.contains("dsa")
            && !algo.contains("ecdsa")
            && !algo.contains("eddsa")
            && key_bits == Some(1024))
        || algo.contains("rc4")
        || algo.contains("3des")
        || algo.contains("des-")
        || algo == "des"
    {
        return 10;
    }

    // RSA-2048, ECDSA P-256, DH-2048, ECDH P-256.
    if (algo.contains("rsa") && key_bits == Some(2048))
        || algo.contains("ecdsa-p256")
        || algo.contains("ecdsa-p-256")
        || algo == "p-256"
        || (algo.contains("ecdsa") && algo.contains("256"))
        || (algo.contains("ecdh") && algo.contains("256"))
        || (algo == "dh" && key_bits == Some(2048))
        || (algo.contains("dh-") && key_bits == Some(2048))
    {
        return 9;
    }

    // RSA-3072, RSA-4096, ECDSA P-384, ECDSA P-521.
    if (algo.contains("rsa") && matches!(key_bits, Some(3072) | Some(4096) | Some(8192)))
        || algo.contains("p-384")
        || algo.contains("p384")
        || algo.contains("p-521")
        || algo.contains("p521")
        || (algo.contains("ecdsa") && (algo.contains("384") || algo.contains("521")))
    {
        return 8;
    }

    // PQC-ready primitives by name.
    if algo.starts_with("ml-kem")
        || algo.starts_with("mlkem")
        || algo.starts_with("kyber")
        || algo.starts_with("ml-dsa")
        || algo.starts_with("mldsa")
        || algo.starts_with("dilithium")
        || algo.starts_with("slh-dsa")
        || algo.starts_with("slhdsa")
        || algo.starts_with("sphincs")
        || algo.contains("falcon")
        || algo.starts_with("hqc")
    {
        return 1;
    }

    // Symmetric primitives that remain safe.
    if algo.contains("aes-256")
        || algo == "aes256"
        || (algo.contains("aes")
            && (algo.contains("gcm") || algo.contains("ccm"))
            && key_bits.map(|b| b >= 256).unwrap_or(false))
        || algo.contains("sha-256")
        || algo.contains("sha256")
        || algo.contains("sha-384")
        || algo.contains("sha384")
        || algo.contains("sha-512")
        || algo.contains("sha512")
        || algo.contains("sha3-")
        || algo.contains("shake")
        || algo.contains("chacha20")
        || algo.contains("poly1305")
        || algo.contains("hmac-sha256")
        || algo.contains("hmac-sha384")
        || algo.contains("hmac-sha512")
    {
        return 0;
    }

    // Asymmetric primitives with no explicit size or fallback ECC names.
    if algo.contains("rsa")
        || algo.contains("ecdsa")
        || algo.contains("ecdh")
        || algo.contains("dh")
        || algo.contains("dsa")
        || algo.contains("ed25519")
        || algo.contains("ed448")
        || algo.contains("x25519")
        || algo.contains("x448")
    {
        // Modern Edwards curves are not quantum-safe but mid-strength classical.
        if algo.contains("ed25519") || algo.contains("x25519") {
            return 8;
        }
        if algo.contains("ed448") || algo.contains("x448") {
            return 8;
        }
        return 9;
    }

    ALGO_UNKNOWN_DEFAULT
}

fn key_size_bits(asset: &CryptoAsset) -> Option<u32> {
    asset
        .parameter_set
        .as_object()
        .and_then(|m| m.get("key_size_bits").or_else(|| m.get("bits")))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
}

pub fn data_sens_score(asset: &CryptoAsset) -> u8 {
    match asset.data_classification {
        Some(Classification::TopSecret) => 10,
        Some(Classification::Secret) => 8,
        Some(Classification::Protected) => 6,
        Some(Classification::OfficialSensitive) => 4,
        Some(Classification::Official) => 2,
        Some(Classification::Unofficial) => 0,
        None => 0,
    }
}

pub fn hndl_score(asset: &CryptoAsset, today: OffsetDateTime, system: Option<&System>) -> u8 {
    let current_year = today.year() as u16;

    let years_remaining = if let Some(year) = asset.data_retention_horizon_year {
        Some(year.saturating_sub(current_year))
    } else if let Some(sys) = system {
        sys.expected_data_lifetime_years
    } else {
        None
    };

    match years_remaining {
        Some(y) if y >= 15 => 10,
        Some(y) if y >= 10 => 8,
        Some(y) if y >= 5 => 6,
        Some(y) if y >= 2 => 3,
        Some(_) => 0,
        None => HNDL_NO_HORIZON_DEFAULT,
    }
}

pub fn system_crit_score(system: Option<&System>) -> u8 {
    match system {
        Some(s) if matches!(s.criticality, Criticality::MissionCritical) || s.is_soci => 10,
        Some(s) if matches!(s.criticality, Criticality::Essential) => 7,
        Some(s) if matches!(s.criticality, Criticality::Standard) => 4,
        Some(_) => 1,
        None => 4,
    }
}

pub fn mig_diff_score(asset: &CryptoAsset) -> u8 {
    match asset.migration_difficulty {
        MigrationDifficulty::HardwareLocked => 10,
        MigrationDifficulty::High => 8,
        MigrationDifficulty::Medium => 6,
        MigrationDifficulty::Low => 3,
        MigrationDifficulty::Trivial => 1,
    }
}

pub fn priority(algo_vuln: u8, hndl: u8, data_sens: u8, sys_crit: u8, mig_diff: u8) -> f32 {
    let raw = (algo_vuln as f32) * 0.30
        + (hndl as f32) * 0.30
        + (data_sens as f32) * 0.15
        + (sys_crit as f32) * 0.15
        + (mig_diff as f32) * 0.10;
    (raw * 10.0).round() / 10.0
}

pub fn triage_tier(priority: f32, mig_diff: u8, algo_vuln: u8) -> u8 {
    if priority >= 7.0 && mig_diff <= 6 {
        1
    } else if priority >= 6.0 || (mig_diff >= 7 && algo_vuln >= 8) {
        2
    } else if algo_vuln >= 7 {
        3
    } else {
        4
    }
}

pub fn recommended_action(tier: u8, asset_type: AssetType) -> String {
    match (tier, asset_type) {
        (1, AssetType::Certificate) => "Reissue with ML-DSA-65 before end of 2028".to_string(),
        (1, AssetType::Key) => {
            "Rotate to ML-KEM-768 or ML-DSA-65 key material before end of 2028".to_string()
        }
        (1, AssetType::Algorithm) => {
            "Replace algorithm with NIST FIPS 203/204/205 equivalent before end of 2028".to_string()
        }
        (1, AssetType::ProtocolEndpoint) => {
            "Migrate endpoint to TLS 1.3 with PQ hybrid KEM by end of 2028".to_string()
        }
        (1, AssetType::LibraryDependency) => {
            "Upgrade dependency to PQC-capable build immediately and pin version".to_string()
        }
        (2, AssetType::Certificate) => {
            "Plan certificate reissuance with ML-DSA before end of 2028".to_string()
        }
        (2, AssetType::Key) => {
            "Schedule key rotation to PQC equivalent inside the 2028 milestone".to_string()
        }
        (2, AssetType::Algorithm) => {
            "Schedule algorithm replacement inside the 2028 milestone window".to_string()
        }
        (2, AssetType::ProtocolEndpoint) => {
            "Plan TLS 1.3 hybrid KEM rollout inside the 2028 milestone window".to_string()
        }
        (2, AssetType::LibraryDependency) => {
            "Upgrade to vendor PQC build when GA; verify roadmap".to_string()
        }
        (3, AssetType::Certificate) => {
            "Track certificate for replacement during the 2029 to 2030 rollout window".to_string()
        }
        (3, AssetType::Key) => {
            "Track key for rotation during the 2029 to 2030 rollout window".to_string()
        }
        (3, AssetType::Algorithm) => {
            "Plan replacement during the 2029 to 2030 rollout window".to_string()
        }
        (3, AssetType::ProtocolEndpoint) => {
            "Plan TLS 1.3 hybrid KEM rollout for 2029-2030".to_string()
        }
        (3, AssetType::LibraryDependency) => {
            "Track vendor PQC roadmap; upgrade before 2030".to_string()
        }
        (_, AssetType::Certificate) => {
            "Monitor; reassess if classification or retention changes".to_string()
        }
        (_, AssetType::Key) => {
            "Monitor; reassess if classification or retention changes".to_string()
        }
        (_, AssetType::Algorithm) => "Monitor; no immediate action required".to_string(),
        (_, AssetType::ProtocolEndpoint) => "Monitor; no immediate action required".to_string(),
        (_, AssetType::LibraryDependency) => {
            "Monitor vendor roadmap; no immediate action required".to_string()
        }
    }
}

pub fn score_asset(
    asset: &CryptoAsset,
    system: Option<&System>,
    today: OffsetDateTime,
) -> RiskScore {
    let algo_vuln = algo_vuln_score(asset);
    let data_sens = data_sens_score(asset);
    let hndl = hndl_score(asset, today, system);
    let sys_crit = system_crit_score(system);
    let mig_diff = mig_diff_score(asset);
    let priority_value = priority(algo_vuln, hndl, data_sens, sys_crit, mig_diff);
    let tier = triage_tier(priority_value, mig_diff, algo_vuln);
    let action = recommended_action(tier, asset.asset_type);

    RiskScore {
        algorithm_vulnerability: algo_vuln,
        data_sensitivity: data_sens,
        harvest_now_decrypt_later: hndl,
        system_criticality: sys_crit,
        migration_difficulty: mig_diff,
        priority: priority_value,
        triage_tier: tier,
        recommended_action: action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::asset::{AssetType, CryptoAsset, MigrationDifficulty, PqcStatus};
    use crate::model::system::{Classification, Criticality};
    use serde_json::json;
    use time::macros::datetime;

    fn algo_asset(name: &str, params: serde_json::Value) -> CryptoAsset {
        let mut a = CryptoAsset::new(
            AssetType::Algorithm,
            name.to_string(),
            name.to_string(),
            PqcStatus::Vulnerable,
            true,
            MigrationDifficulty::Medium,
        );
        a.parameter_set = params;
        a
    }

    #[test]
    fn algo_md5_is_broken() {
        assert_eq!(algo_vuln_score(&algo_asset("MD5", json!({}))), 10);
    }

    #[test]
    fn algo_sha1_is_broken() {
        assert_eq!(algo_vuln_score(&algo_asset("SHA-1", json!({}))), 10);
        assert_eq!(algo_vuln_score(&algo_asset("sha1", json!({}))), 10);
    }

    #[test]
    fn algo_rsa1024_is_broken() {
        assert_eq!(
            algo_vuln_score(&algo_asset("RSA", json!({"key_size_bits": 1024}))),
            10
        );
    }

    #[test]
    fn algo_dsa1024_is_broken() {
        assert_eq!(
            algo_vuln_score(&algo_asset("DSA", json!({"key_size_bits": 1024}))),
            10
        );
    }

    #[test]
    fn algo_3des_is_broken() {
        assert_eq!(algo_vuln_score(&algo_asset("3DES", json!({}))), 10);
    }

    #[test]
    fn algo_rc4_is_broken() {
        assert_eq!(algo_vuln_score(&algo_asset("RC4", json!({}))), 10);
    }

    #[test]
    fn algo_rsa2048_is_classic_strong() {
        assert_eq!(
            algo_vuln_score(&algo_asset("RSA", json!({"key_size_bits": 2048}))),
            9
        );
    }

    #[test]
    fn algo_ecdsa_p256_is_9() {
        assert_eq!(algo_vuln_score(&algo_asset("ECDSA-P-256", json!({}))), 9);
        assert_eq!(algo_vuln_score(&algo_asset("ECDSA-256", json!({}))), 9);
    }

    #[test]
    fn algo_ecdh_256_is_9() {
        assert_eq!(algo_vuln_score(&algo_asset("ECDH-256", json!({}))), 9);
    }

    #[test]
    fn algo_dh_2048_is_9() {
        assert_eq!(
            algo_vuln_score(&algo_asset("DH", json!({"key_size_bits": 2048}))),
            9
        );
    }

    #[test]
    fn algo_rsa3072_is_8() {
        assert_eq!(
            algo_vuln_score(&algo_asset("RSA", json!({"key_size_bits": 3072}))),
            8
        );
    }

    #[test]
    fn algo_rsa4096_is_8() {
        assert_eq!(
            algo_vuln_score(&algo_asset("RSA", json!({"key_size_bits": 4096}))),
            8
        );
    }

    #[test]
    fn algo_ecdsa_p384_p521_is_8() {
        assert_eq!(algo_vuln_score(&algo_asset("ECDSA-P-384", json!({}))), 8);
        assert_eq!(algo_vuln_score(&algo_asset("ECDSA-P-521", json!({}))), 8);
    }

    #[test]
    fn algo_x25519_is_8() {
        assert_eq!(algo_vuln_score(&algo_asset("X25519", json!({}))), 8);
        assert_eq!(algo_vuln_score(&algo_asset("Ed25519", json!({}))), 8);
        assert_eq!(algo_vuln_score(&algo_asset("X448", json!({}))), 8);
    }

    #[test]
    fn algo_hybrid_is_5() {
        let mut a = algo_asset("X25519MLKEM768", json!({}));
        a.pqc_status = PqcStatus::Hybrid;
        assert_eq!(algo_vuln_score(&a), 5);
    }

    #[test]
    fn algo_ml_kem_resistant() {
        let mut a = algo_asset("ML-KEM-768", json!({}));
        a.pqc_status = PqcStatus::Resistant;
        assert_eq!(algo_vuln_score(&a), 1);
    }

    #[test]
    fn algo_ml_kem_by_name_falls_into_pqc_branch() {
        // Without pqc_status flag, name-based detection still scores low.
        let a = algo_asset("ML-KEM-768", json!({}));
        assert_eq!(algo_vuln_score(&a), 1);
    }

    #[test]
    fn algo_ml_dsa_by_name() {
        assert_eq!(algo_vuln_score(&algo_asset("ML-DSA-65", json!({}))), 1);
        assert_eq!(algo_vuln_score(&algo_asset("dilithium3", json!({}))), 1);
        assert_eq!(
            algo_vuln_score(&algo_asset("SLH-DSA-SHA2-128s", json!({}))),
            1
        );
        assert_eq!(algo_vuln_score(&algo_asset("falcon-512", json!({}))), 1);
        assert_eq!(algo_vuln_score(&algo_asset("kyber768", json!({}))), 1);
        assert_eq!(algo_vuln_score(&algo_asset("hqc-128", json!({}))), 1);
        assert_eq!(algo_vuln_score(&algo_asset("sphincs+", json!({}))), 1);
    }

    #[test]
    fn algo_aes256_is_safe() {
        assert_eq!(algo_vuln_score(&algo_asset("AES-256-GCM", json!({}))), 0);
        assert_eq!(algo_vuln_score(&algo_asset("AES256", json!({}))), 0);
    }

    #[test]
    fn algo_sha256_plus_is_safe() {
        assert_eq!(algo_vuln_score(&algo_asset("SHA-256", json!({}))), 0);
        assert_eq!(algo_vuln_score(&algo_asset("SHA384", json!({}))), 0);
        assert_eq!(algo_vuln_score(&algo_asset("SHA-512", json!({}))), 0);
        assert_eq!(algo_vuln_score(&algo_asset("SHA3-256", json!({}))), 0);
        assert_eq!(algo_vuln_score(&algo_asset("SHAKE128", json!({}))), 0);
    }

    #[test]
    fn algo_chacha20_is_safe() {
        assert_eq!(
            algo_vuln_score(&algo_asset("ChaCha20-Poly1305", json!({}))),
            0
        );
    }

    #[test]
    fn algo_symmetric_ok_status_overrides_to_zero() {
        let mut a = algo_asset("some-cipher", json!({}));
        a.pqc_status = PqcStatus::SymmetricOk;
        assert_eq!(algo_vuln_score(&a), 0);
    }

    #[test]
    fn algo_unknown_is_7() {
        assert_eq!(
            algo_vuln_score(&algo_asset("FrobnicatorCipher", json!({}))),
            7
        );
    }

    #[test]
    fn algo_rsa_unknown_size_falls_back_to_9() {
        assert_eq!(algo_vuln_score(&algo_asset("RSA", json!({}))), 9);
    }

    #[test]
    fn algo_dsa_unknown_size_falls_back_to_9() {
        assert_eq!(algo_vuln_score(&algo_asset("DSA", json!({}))), 9);
    }

    #[test]
    fn data_sens_all_classes() {
        let mk = |c: Option<Classification>| {
            let mut a = algo_asset("RSA", json!({}));
            a.data_classification = c;
            a
        };
        assert_eq!(data_sens_score(&mk(Some(Classification::TopSecret))), 10);
        assert_eq!(data_sens_score(&mk(Some(Classification::Secret))), 8);
        assert_eq!(data_sens_score(&mk(Some(Classification::Protected))), 6);
        assert_eq!(
            data_sens_score(&mk(Some(Classification::OfficialSensitive))),
            4
        );
        assert_eq!(data_sens_score(&mk(Some(Classification::Official))), 2);
        assert_eq!(data_sens_score(&mk(Some(Classification::Unofficial))), 0);
        assert_eq!(data_sens_score(&mk(None)), 0);
    }

    fn today() -> OffsetDateTime {
        datetime!(2026-05-18 12:00 UTC)
    }

    #[test]
    fn hndl_buckets() {
        let mk = |year: Option<u16>| {
            let mut a = algo_asset("RSA", json!({}));
            a.data_retention_horizon_year = year;
            a
        };
        assert_eq!(hndl_score(&mk(Some(2050)), today(), None), 10);
        assert_eq!(hndl_score(&mk(Some(2041)), today(), None), 10);
        assert_eq!(hndl_score(&mk(Some(2036)), today(), None), 8);
        assert_eq!(hndl_score(&mk(Some(2031)), today(), None), 6);
        assert_eq!(hndl_score(&mk(Some(2028)), today(), None), 3);
        assert_eq!(hndl_score(&mk(Some(2027)), today(), None), 0);
        assert_eq!(hndl_score(&mk(Some(2026)), today(), None), 0);
    }

    #[test]
    fn hndl_falls_back_to_system_lifetime() {
        let a = algo_asset("RSA", json!({}));
        let sys = System::new(
            "S".into(),
            None,
            Classification::Official,
            Criticality::Standard,
            false,
            Some(12),
        );
        assert_eq!(hndl_score(&a, today(), Some(&sys)), 8);
    }

    #[test]
    fn hndl_no_data_defaults_to_5() {
        let a = algo_asset("RSA", json!({}));
        assert_eq!(hndl_score(&a, today(), None), 5);
    }

    #[test]
    fn system_crit_all_branches() {
        let mk_sys = |c: Criticality, is_soci: bool| {
            System::new("S".into(), None, Classification::Official, c, is_soci, None)
        };
        assert_eq!(
            system_crit_score(Some(&mk_sys(Criticality::MissionCritical, false))),
            10
        );
        assert_eq!(
            system_crit_score(Some(&mk_sys(Criticality::Essential, false))),
            7
        );
        assert_eq!(
            system_crit_score(Some(&mk_sys(Criticality::Standard, false))),
            4
        );
        assert_eq!(system_crit_score(Some(&mk_sys(Criticality::Low, false))), 1);
        assert_eq!(system_crit_score(Some(&mk_sys(Criticality::Low, true))), 10);
        assert_eq!(system_crit_score(None), 4);
    }

    #[test]
    fn mig_diff_all_branches() {
        let mk = |d: MigrationDifficulty| {
            let mut a = algo_asset("RSA", json!({}));
            a.migration_difficulty = d;
            a
        };
        assert_eq!(mig_diff_score(&mk(MigrationDifficulty::HardwareLocked)), 10);
        assert_eq!(mig_diff_score(&mk(MigrationDifficulty::High)), 8);
        assert_eq!(mig_diff_score(&mk(MigrationDifficulty::Medium)), 6);
        assert_eq!(mig_diff_score(&mk(MigrationDifficulty::Low)), 3);
        assert_eq!(mig_diff_score(&mk(MigrationDifficulty::Trivial)), 1);
    }

    #[test]
    fn priority_formula_rounds_to_one_decimal() {
        // 10*0.3 + 10*0.3 + 10*0.15 + 10*0.15 + 10*0.1 = 10.0
        assert!((priority(10, 10, 10, 10, 10) - 10.0).abs() < 0.001);
        // 5*0.3 + 5*0.3 + 0*0.15 + 0*0.15 + 0*0.1 = 3.0
        assert!((priority(5, 5, 0, 0, 0) - 3.0).abs() < 0.001);
        // Rounding edge: 7*0.3+7*0.3+3*0.15+3*0.15+3*0.1 = 2.1+2.1+0.45+0.45+0.3 = 5.4
        let p = priority(7, 7, 3, 3, 3);
        assert!((p - 5.4).abs() < 0.001);
    }

    #[test]
    fn tier_1_condition() {
        // priority >= 7 and mig_diff <= 6
        let p = priority(10, 10, 10, 0, 1);
        assert!(p >= 7.0, "p = {}", p);
        assert_eq!(triage_tier(p, 1, 10), 1);
    }

    #[test]
    fn tier_2_condition_via_priority() {
        // priority >= 6 but mig_diff > 6 keeps us out of tier 1
        let p = priority(10, 10, 0, 0, 8);
        assert!((6.0..7.0).contains(&p), "p = {}", p);
        assert_eq!(triage_tier(p, 8, 10), 2);
    }

    #[test]
    fn tier_2_condition_via_hardware_and_vuln() {
        // priority < 6 but mig_diff >= 7 and algo_vuln >= 8
        let p = priority(8, 0, 0, 0, 10);
        assert!(p < 6.0);
        assert_eq!(triage_tier(p, 10, 8), 2);
    }

    #[test]
    fn tier_3_condition() {
        // priority < 6 and algo_vuln >= 7 and mig_diff < 7
        let p = priority(7, 0, 0, 0, 1);
        assert!(p < 6.0);
        assert_eq!(triage_tier(p, 1, 7), 3);
    }

    #[test]
    fn tier_4_fallthrough() {
        let p = priority(0, 0, 0, 0, 1);
        assert_eq!(triage_tier(p, 1, 0), 4);
    }

    #[test]
    fn recommended_action_covers_all_combinations() {
        for tier in [1u8, 2, 3, 4] {
            for at in [
                AssetType::Algorithm,
                AssetType::Certificate,
                AssetType::Key,
                AssetType::ProtocolEndpoint,
                AssetType::LibraryDependency,
            ] {
                let s = recommended_action(tier, at);
                assert!(!s.is_empty(), "empty action for tier {} {:?}", tier, at);
            }
        }
    }

    #[test]
    fn score_asset_end_to_end() {
        let mut a = algo_asset("RSA", json!({"key_size_bits": 2048}));
        a.asset_type = AssetType::Certificate;
        a.data_classification = Some(Classification::Protected);
        a.data_retention_horizon_year = Some(2050);
        a.migration_difficulty = MigrationDifficulty::Low;
        let sys = System::new(
            "Payments".into(),
            None,
            Classification::Protected,
            Criticality::MissionCritical,
            true,
            None,
        );
        let s = score_asset(&a, Some(&sys), today());
        assert_eq!(s.algorithm_vulnerability, 9);
        assert_eq!(s.data_sensitivity, 6);
        assert_eq!(s.harvest_now_decrypt_later, 10);
        assert_eq!(s.system_criticality, 10);
        assert_eq!(s.migration_difficulty, 3);
        assert!(s.priority >= 7.0);
        assert_eq!(s.triage_tier, 1);
        assert!(s.recommended_action.contains("ML-DSA"));
    }
}
