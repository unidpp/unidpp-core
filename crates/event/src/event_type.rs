//! Event classes: the 15 post-sale classes (E1-E15) plus the
//! transformation / structural / edge-visibility vocabulary.

unidpp_model::str_enum! {
    /// Typed event classes. The first fifteen variants (in declaration
    /// order) are the the UniDPP design framework post-sale taxonomy E1-E15; the rest are the
    /// transformation, structural, and edge-visibility classes.
    pub enum EventType {
        // E1-E15 (post-sale taxonomy).
        CustodyTransfer => "custody.transfer",
        PartReplace => "part.replace",
        RepairPerform => "repair.perform",
        ProductModify => "product.modify",
        SoftwareUpdate => "software.update",
        UpgradeInstall => "upgrade.install",
        RefurbishRemanufacture => "refurbish.remanufacture",
        ConsumableReplace => "consumable.replace",
        RecallCampaign => "recall.campaign",
        Correction => "correction",
        StatusChange => "status.change",
        FlagSecurity => "flag.security",
        Decompose => "decompose",
        InspectionStamp => "inspection.stamp",
        MilestoneRecord => "milestone.record",
        // Transformation algebra.
        Split => "split",
        Combine => "combine",
        EndOfWaste => "end-of-waste",
        // Structural.
        Install => "install",
        Uninstall => "uninstall",
        // Passport lifecycle.
        Issuance => "issuance",
        // Edge visibility classes.
        EdgeVisibilityChange => "edge.visibility.change",
        EscrowDisclosure => "escrow.disclosure",
    }
}

impl EventType {
    /// The E1-E15 post-sale classes (declaration order).
    pub fn post_sale_classes() -> &'static [EventType] {
        &[
            EventType::CustodyTransfer,
            EventType::PartReplace,
            EventType::RepairPerform,
            EventType::ProductModify,
            EventType::SoftwareUpdate,
            EventType::UpgradeInstall,
            EventType::RefurbishRemanufacture,
            EventType::ConsumableReplace,
            EventType::RecallCampaign,
            EventType::Correction,
            EventType::StatusChange,
            EventType::FlagSecurity,
            EventType::Decompose,
            EventType::InspectionStamp,
            EventType::MilestoneRecord,
        ]
    }

    pub fn is_post_sale_class(&self) -> bool {
        Self::post_sale_classes().contains(self)
    }

    pub fn is_transformation(&self) -> bool {
        matches!(
            self,
            EventType::Split | EventType::Combine | EventType::EndOfWaste | EventType::Decompose
        )
    }

    pub fn is_structural(&self) -> bool {
        matches!(
            self,
            EventType::Install
                | EventType::Uninstall
                | EventType::UpgradeInstall
                | EventType::PartReplace
        )
    }

    pub fn is_edge_visibility_class(&self) -> bool {
        matches!(
            self,
            EventType::EdgeVisibilityChange | EventType::EscrowDisclosure
        )
    }

    /// Default appending role (taxonomy: event -> who appends).
    pub fn appender_role(&self) -> &'static str {
        match self {
            EventType::CustodyTransfer => "custodian (+counterparty)",
            EventType::PartReplace | EventType::RepairPerform => "repairer",
            EventType::ProductModify => "accredited modifier",
            EventType::SoftwareUpdate => "economic operator / service",
            EventType::UpgradeInstall => "installer",
            EventType::RefurbishRemanufacture => "refurbisher",
            EventType::ConsumableReplace => "any, per profile",
            EventType::RecallCampaign => "regulator / economic operator",
            EventType::Correction => "economic operator with attestation",
            EventType::StatusChange => "regulator / economic operator per profile",
            EventType::FlagSecurity => "authority + registry",
            EventType::Decompose => "recycler (accredited for claims)",
            EventType::InspectionStamp => "any verifier",
            EventType::MilestoneRecord => "device",
            EventType::Split | EventType::Combine => "custodian (transformer)",
            EventType::EndOfWaste => "accredited actor",
            EventType::Install | EventType::Uninstall => "installer / repairer",
            EventType::Issuance => "issuing authority",
            EventType::EdgeVisibilityChange | EventType::EscrowDisclosure => "edge owner / trustee",
        }
    }

    pub fn number(&self) -> Option<&'static str> {
        let classes = Self::post_sale_classes();
        classes.iter().position(|c| c == self).map(|i| match i {
            0 => "E1",
            1 => "E2",
            2 => "E3",
            3 => "E4",
            4 => "E5",
            5 => "E6",
            6 => "E7",
            7 => "E8",
            8 => "E9",
            9 => "E10",
            10 => "E11",
            11 => "E12",
            12 => "E13",
            13 => "E14",
            _ => "E15",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifteen_post_sale_classes() {
        assert_eq!(EventType::post_sale_classes().len(), 15);
        assert!(EventType::CustodyTransfer.is_post_sale_class());
        assert!(EventType::MilestoneRecord.is_post_sale_class());
        assert!(!EventType::Split.is_post_sale_class());
        assert_eq!(EventType::CustodyTransfer.number(), Some("E1"));
        assert_eq!(EventType::MilestoneRecord.number(), Some("E15"));
        assert_eq!(EventType::Split.number(), None);
    }

    #[test]
    fn casing_and_separators_parse() {
        assert_eq!(
            "Custody.Transfer".parse::<EventType>().unwrap(),
            EventType::CustodyTransfer
        );
        assert_eq!(
            "END_OF_WASTE".parse::<EventType>().unwrap(),
            EventType::EndOfWaste
        );
        assert_eq!(
            "endofwaste".parse::<EventType>().unwrap(),
            EventType::EndOfWaste
        );
        assert!("nonsense".parse::<EventType>().is_err());
        assert_eq!(
            EventType::EdgeVisibilityChange.to_string(),
            "edge.visibility.change"
        );
    }
}
