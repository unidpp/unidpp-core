//! QR byte-capacity model (ISO/IEC 18004 data-capacity tables, byte mode).
//!
//! Byte-mode data capacity per (version 1..=40, error-correction level).
//! EN 18220-class carriers are QR codes; the packer budgets the Tier-A
//! payload against these tables.

unidpp_model::str_enum! {
    /// Error-correction level.
    pub enum EcLevel {
        L => "l",
        M => "m",
        Q => "q",
        H => "h",
    }
}

const CAP_L: [u32; 40] = [
    17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520, 586, 644, 718, 792,
    858, 929, 1003, 1091, 1171, 1273, 1367, 1465, 1528, 1628, 1732, 1840, 1952, 2068, 2188, 2303,
    2431, 2563, 2699, 2809, 2953,
];
const CAP_M: [u32; 40] = [
    14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560, 624,
    666, 711, 779, 857, 911, 997, 1059, 1125, 1190, 1264, 1370, 1452, 1538, 1628, 1722, 1809,
    1911, 1989, 2099, 2213, 2331,
];
const CAP_Q: [u32; 40] = [
    11, 20, 32, 46, 60, 74, 86, 108, 130, 151, 177, 203, 241, 258, 292, 322, 364, 394, 442, 482,
    509, 565, 611, 661, 715, 751, 805, 868, 908, 982, 1030, 1112, 1168, 1228, 1283, 1351, 1423,
    1499, 1579, 1663,
];
const CAP_H: [u32; 40] = [
    7, 14, 24, 34, 44, 58, 64, 84, 98, 119, 137, 155, 177, 194, 220, 250, 280, 310, 338, 382,
    403, 439, 461, 511, 535, 593, 625, 658, 698, 742, 790, 842, 898, 958, 983, 1051, 1093, 1139,
    1219, 1273,
];

/// Byte-mode capacity of QR `version` (1..=40) at `ec`.
pub fn byte_capacity(version: u8, ec: EcLevel) -> u32 {
    assert!((1..=40).contains(&version), "QR version out of range");
    let table: &[u32; 40] = match ec {
        EcLevel::L => &CAP_L,
        EcLevel::M => &CAP_M,
        EcLevel::Q => &CAP_Q,
        EcLevel::H => &CAP_H,
    };
    table[(version - 1) as usize]
}

/// Smallest QR version that holds `len` bytes at `ec`, if any.
pub fn min_version_for(len: usize, ec: EcLevel) -> Option<u8> {
    (1u8..=40).find(|&v| byte_capacity(v, ec) as usize >= len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_capacities() {
        assert_eq!(byte_capacity(1, EcLevel::L), 17);
        assert_eq!(byte_capacity(1, EcLevel::H), 7);
        assert_eq!(byte_capacity(10, EcLevel::M), 213);
        assert_eq!(byte_capacity(40, EcLevel::L), 2953);
        assert_eq!(byte_capacity(40, EcLevel::M), 2331);
        assert_eq!(byte_capacity(40, EcLevel::Q), 1663);
        assert_eq!(byte_capacity(40, EcLevel::H), 1273);
    }

    #[test]
    fn version_selection() {
        assert_eq!(min_version_for(17, EcLevel::L), Some(1));
        assert_eq!(min_version_for(18, EcLevel::L), Some(2));
        assert_eq!(min_version_for(2953, EcLevel::L), Some(40));
        assert_eq!(min_version_for(2954, EcLevel::L), None);
        assert_eq!(min_version_for(7, EcLevel::H), Some(1));
    }

    #[test]
    fn casing_normalization() {
        assert_eq!("H".parse::<EcLevel>().unwrap(), EcLevel::H);
        assert_eq!("m".parse::<EcLevel>().unwrap(), EcLevel::M);
        assert_eq!("L".parse::<EcLevel>().unwrap(), EcLevel::L);
        assert_eq!(EcLevel::Q.to_string(), "q");
        assert!("HIGH".parse::<EcLevel>().is_err());
    }
}
