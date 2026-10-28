use std::path::PathBuf;
use egui_file_dialog::FileDialog;
use amber_core::FailureReason;

#[derive(PartialEq)]
pub enum Page {
    Welcome,
    Explanation,
    Functions,
    VerifyTreeAndFile,
    VerifyProof,
    BuildProof,
    WelcomeTimestamp,
    OverviewTimestamp,
    BuildTimestamp,
    CorpusDesc,
    CorpusMotiv,
    UserDesc,
    ExamineExplain,
    WriteBlockchainMessage,
    FinalizeTimestamp,
    Goodbye,
}
pub struct VerificationStatus {
    pub provided_merkle_file_dialog: FileDialog,
    pub provided_merkle_file: Option<PathBuf>,
    pub provided_explain_file_dialog: FileDialog,
    pub provided_explain_file: Option<PathBuf>,
    pub verify_status: Option<String>,
    pub verify_attempted: bool,
    pub verified: Option<bool>,
    pub reason: Option<FailureReason>,
    pub show_more: bool, 
    pub tx_hash: Option<String>,
    pub block: Option<String>,
    pub utc: Option<i64>,
}

impl VerificationStatus {
    pub fn new() -> Self {
        Self {
            provided_merkle_file_dialog: FileDialog::new(),
            provided_merkle_file: None,
            provided_explain_file_dialog: FileDialog::new(),
            provided_explain_file: None,
            verify_status: None,
            verify_attempted: false,
            verified: None,
            reason: None,
            show_more: false,
            tx_hash: None,
            block: None,
            utc: None,
        }
    }

    pub fn clear_verify_state(&mut self) {
        self.verify_status = None;
        self.verified = None;
        self.tx_hash = None;
        self.block = None;
        self.utc = None;
    }
}

pub struct AuthenticationStatus {
    pub provided_file_dialog: FileDialog,
    pub provided_file: Option<PathBuf>,
    pub auth_attempted: bool,
    pub file_authenticated: Option<bool>,
    pub file_auth_status: Option<String>,
}

impl AuthenticationStatus {
    pub fn new() -> Self {
        Self {
            provided_file_dialog: FileDialog::new(),
            provided_file: None,
            auth_attempted: false,
            file_authenticated: None,
            file_auth_status: None,
        }
    }

    pub fn clear_auth_state(&mut self) {
        self.file_auth_status = None;
        self.file_authenticated = None;
    }
}

pub struct ProofStatus {
    pub provided_proof_file_dialog: FileDialog,
    pub provided_proof_file: Option<PathBuf>,
    pub provided_file_dialog: FileDialog,
    pub provided_file: Option<PathBuf>,
    pub proof_auth_status: Option<String>,
    pub proof_auth_attempted: bool,
    pub proof_authenticated: Option<bool>,
    pub proof_auth_reason: Option<FailureReason>,
    pub proof_utc: Option<i64>,
    pub proof_tx_hash: Option<String>,
    pub proof_block: Option<String>,
    pub proof_date: Option<String>,
    pub proof_time: Option<String>,
    pub proof_id: Option<String>,
    pub show_more: bool,
}

impl ProofStatus {
    pub fn new() -> Self {
        Self {
            provided_proof_file_dialog: FileDialog::new(),
            provided_proof_file: None,
            provided_file_dialog: FileDialog::new(),
            provided_file: None,
            proof_auth_status: None,
            proof_auth_attempted: false,
            proof_authenticated: None,
            proof_auth_reason: None,
            proof_utc: None,
            proof_tx_hash: None,
            proof_block: None,
            proof_date: None,
            proof_time: None,
            proof_id: None,
            show_more: false,
        }
    }
}

pub struct BuildProofStatus {
    pub status: Option<String>,
    pub merkle_file_dialog: FileDialog,
    pub merkle_file: Option<PathBuf>,
    pub explain_file_dialog: FileDialog,
    pub explain_file: Option<PathBuf>,
    pub proven_file_dialog: FileDialog,
    pub proven_file: Option<PathBuf>,
    pub corpus_name: String,
    pub proof_attempted: bool,
    pub proof_verified: bool,
    pub proof_reason: Option<FailureReason>,
    pub proof_string: String,
}

impl BuildProofStatus {
    pub fn new() -> Self {
        Self {
            status: None,
            merkle_file_dialog: FileDialog::new(),
            merkle_file: None,
            explain_file_dialog: FileDialog::new(),
            explain_file: None,
            proven_file_dialog: FileDialog::new(),
            proven_file: None,
            corpus_name: "".to_string(),
            proof_attempted: false,
            proof_verified: false,
            proof_reason: None,
            proof_string: "".to_string(),
        }
    }
}

pub struct BuildTimestampStatus {
    pub scouts_honor: bool,
    pub corpus_desc_source: bool,
    pub corpus_desc_dialog: FileDialog,
    pub corpus_desc_file: Option<PathBuf>,
    pub corpus_desc: String,
    pub corpus_motiv_source: bool,
    pub corpus_motiv_dialog: FileDialog,
    pub corpus_motiv_file: Option<PathBuf>,
    pub corpus_motiv: String,
    pub user_desc_source: bool,
    pub user_desc_dialog: FileDialog,
    pub user_desc_file: Option<PathBuf>,
    pub user_desc: String,
    pub show_signing: bool,
    pub hashes: bool,
    pub hashes_explain: bool,
    pub directory_dialog: FileDialog,
    pub directory: Option<PathBuf>,
    pub hash_file_dialog: FileDialog,
    pub hash_file: Option<PathBuf>,
    pub output_dir_dialog: FileDialog,
    pub output_dir: Option<PathBuf>,
    pub corpus_name: String,
    pub identifier: String,
    pub build_attempted: bool,
    pub build_status: Option<String>,
    pub tree_exists: bool,
    pub root_hash: Option<String>,
    pub num_leaves: Option<usize>,
    pub tree_file: Option<PathBuf>,
    pub explain_file: Option<PathBuf>,
    pub explain_string: String,
    pub show_explain: bool,
    pub explain_shown: bool,
    pub tag_string: String,
    pub show_tag_explanation: bool,
    pub finalize_status: Option<String>,
    pub tree_verified: bool,
    pub tree_verified_reason: Option<FailureReason>,
    pub tx_hash_string: String,
    pub show_more: bool,
}

impl BuildTimestampStatus {
    pub fn new() -> Self {
        Self {
            scouts_honor: false,
            corpus_desc_source: false,
            corpus_desc_dialog: FileDialog::new(),
            corpus_desc_file: None,
            corpus_desc: "".to_string(),
            corpus_motiv_source: false,
            corpus_motiv_dialog: FileDialog::new(),
            corpus_motiv_file: None,
            corpus_motiv: "".to_string(),
            user_desc_source: false,
            user_desc_dialog: FileDialog::new(),
            user_desc_file: None,
            user_desc: "".to_string(),
            show_signing: false,
            hashes: false,
            hashes_explain: false,
            directory_dialog: FileDialog::new(),
            directory: None,
            hash_file_dialog: FileDialog::new(),
            hash_file: None,
            output_dir_dialog: FileDialog::new(),
            output_dir: None,
            corpus_name: "".to_string(),
            identifier: "".to_string(),
            build_attempted: false,
            build_status: None,
            tree_exists: false,
            tree_file: None,
            explain_file: None,
            explain_string: "".to_string(),
            show_explain: false,
            explain_shown: false,
            tag_string: "".to_string(),
            show_tag_explanation: false,
            root_hash: None,
            num_leaves: None,
            finalize_status: None,
            tree_verified: false,
            tree_verified_reason: None,
            tx_hash_string: "".to_string(),
            show_more: false,
        }
    }

    pub fn reset_corpus_desc_state(&mut self) {
        self.corpus_desc_dialog = FileDialog::new();
        self.corpus_desc_file = None;
        self.corpus_desc = "".to_string();
    }

    pub fn reset_corpus_motiv_state(&mut self) {
        self.corpus_motiv_dialog = FileDialog::new();
        self.corpus_motiv_file = None;
        self.corpus_motiv = "".to_string();
    }

    pub fn reset_user_desc_state(&mut self) {
        self.user_desc_dialog = FileDialog::new();
        self.user_desc_file = None;
        self.user_desc = "".to_string();
    }

    pub fn reset_prelim_build_state(&mut self) {
        self.build_attempted = false;
        self.build_status = None;
        self.tree_exists = false;
    }

    pub fn reset_finalize_state(&mut self) {
        self.finalize_status = None;
        self.tree_verified=  false;
        self.tree_verified_reason = None;
        self.tx_hash_string = "".to_string();
    }
}
