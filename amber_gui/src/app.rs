
use std::fs::read_to_string;

use amber_core::{FailureReason, Session, make_proof, verify_proof};
use crate::status::{AuthenticationStatus, BuildProofStatus, BuildTimestampStatus, Page, ProofStatus, VerificationStatus};
use hex_fmt::HexFmt;
use chrono;
use std::sync::mpsc::self;
use std::thread;

pub fn convert_utc_to_datetime(utc_seconds: i64) -> (String, String) {
    let utc = chrono::DateTime::from_timestamp(utc_seconds, 0).unwrap();
    let date = format!("{}", utc.format("%B %e, %Y").to_string());
    let time = format!("{}", utc.format("%H:%M").to_string());
    (date, time)
}

/// We derive Deserialize/Serialize so we can persist app state on shutdown.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct TemplateApp {
    #[serde(skip)]
    page: Page,
    #[serde(skip)]
    session: Session,
    #[serde(skip)]
    ver_stat: VerificationStatus,
    #[serde(skip)]
    auth_stat: AuthenticationStatus,
    #[serde(skip)]
    proof_stat: ProofStatus,
    #[serde(skip)]
    build_pf_stat: BuildProofStatus,
    #[serde(skip)]
    build_ts_stat: BuildTimestampStatus,
}

impl Default for TemplateApp {
    fn default() -> Self {
        Self {
            page: Page::Welcome,
            session: Session::new(),
            ver_stat: VerificationStatus::new(),
            auth_stat: AuthenticationStatus::new(),
            proof_stat: ProofStatus::new(),
            build_pf_stat: BuildProofStatus::new(),
            build_ts_stat: BuildTimestampStatus::new(),
        }
    }
}

impl TemplateApp {
    /// Called once before the first frame.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        }
    }    
    
    fn jump_to(&mut self, target: Page) {
        // if you're returning to the welcome page, clear all state.
        if target == Page::Welcome || target == Page::Functions {
            self.session = Session::new();
            self.ver_stat = VerificationStatus::new();
            self.auth_stat = AuthenticationStatus::new();
            self.proof_stat = ProofStatus::new();
            self.build_pf_stat = BuildProofStatus::new();
            self.build_ts_stat = BuildTimestampStatus::new();
        }
        self.page = target;
    }

    fn start_verify(&mut self) {
        self.ver_stat.verify_attempted = true;
        let (tx, rx) = mpsc::channel();
        self.ver_stat.async_result_rx = Some(rx);
        self.ver_stat.async_running = true;

        let tree_filepath = self.ver_stat.provided_merkle_file.clone();
        let explain_filepath = self.ver_stat.provided_explain_file.clone();

        thread::spawn(move || {
            let result = amber_core::verify_tree_async(tree_filepath.unwrap(), explain_filepath.unwrap()); 
            let _ = tx.send(result);
        });
    }

    fn finish_verify(&mut self) {
        if let Some(rx) = &self.ver_stat.async_result_rx {
            if let Ok((result, tree, reason)) = rx.try_recv() {
                self.ver_stat.async_result_rx = None;
                self.ver_stat.async_running = false;
                self.ver_stat.verified = Some(result);
                self.ver_stat.reason = Some(reason);
                self.ver_stat.tree = tree;
                if self.ver_stat.verified.unwrap() {
                    self.ver_stat.tx_hash = Some(format!("{}", HexFmt(self.ver_stat.tree.as_ref().unwrap().tx_hash)));
                    self.ver_stat.block = Some(self.ver_stat.tree.as_ref().unwrap().block_height.to_string());
                    self.ver_stat.utc = Some(self.ver_stat.tree.as_ref().unwrap().utc_timestamp);
                }
            }
        }
    }

    fn authenticate_file(&mut self) {
        if self.ver_stat.verified.unwrap() {
            self.auth_stat.auth_attempted = true;
            if self.ver_stat.tree.is_some() && self.auth_stat.provided_file.is_some() {
                let auth_file = self.auth_stat.provided_file.as_ref().unwrap().to_str().unwrap();
                let result = self.ver_stat.tree.as_ref().unwrap().tree.verify_from_file(auth_file);
                self.auth_stat.file_authenticated = Some(result);
                self.auth_stat.file_auth_status = Some("Done.".to_string());
            }
            else {
                self.auth_stat.file_auth_status = Some("You must specify a file to authenticate.".to_string());
            }
        }

        else {
            self.auth_stat.file_auth_status = Some("You must verify a merkle tree before you authenticate files!".to_string())
        }
    }

    fn verify_proof(&mut self) {
        if self.proof_stat.provided_file.is_some() && self.proof_stat.provided_file.is_some() {
            let proof_file_path_buf = self.proof_stat.provided_proof_file.clone().unwrap();
            let proof_file_path = proof_file_path_buf.to_str().unwrap();
            let file_path_buf = self.proof_stat.provided_file.clone().unwrap();
            let file_path = file_path_buf.to_str().unwrap();
            let (verified, reason, utc, tx_hash, block, date, time, identifier) = verify_proof(file_path, proof_file_path);
            self.proof_stat.proof_auth_attempted = true;
            self.proof_stat.proof_authenticated = Some(verified);
            self.proof_stat.proof_auth_reason = Some(reason);
            self.proof_stat.proof_utc = Some(utc);
            self.proof_stat.proof_tx_hash = Some(tx_hash);
            self.proof_stat.proof_block = Some(block);
            self.proof_stat.proof_date = Some(date);
            self.proof_stat.proof_time = Some(time);
            self.proof_stat.proof_id = Some(identifier);
            self.proof_stat.proof_auth_status = Some("Proof verification complete.".to_string());
        }
        else {
            self.proof_stat.proof_auth_status = Some("You must specify a proof file and a file to verify.".to_string());
        }
    }

    fn build_proof(&mut self) {
        if self.build_pf_stat.proven_file.is_some() && self.build_pf_stat.merkle_file.is_some() {
            self.build_pf_stat.proof_attempted = true;
            let file_path_buf = self.build_pf_stat.proven_file.clone().unwrap();
            let file_path = file_path_buf.to_str().unwrap();
            let merkle_path_buf = self.build_pf_stat.merkle_file.clone().unwrap();
            let merkle_path = merkle_path_buf.to_str().unwrap();
            let explain_path_buf = self.build_pf_stat.explain_file.clone().unwrap();
            let explain_path = explain_path_buf.to_str().unwrap();
            let corpus_name = &self.build_pf_stat.corpus_name;
            let (result, reason) = make_proof(file_path, merkle_path, explain_path, &corpus_name);
            if result {
                self.build_pf_stat.status = Some("Wrote proof to file.".to_string());
                self.build_pf_stat.proof_verified = true;
                let output_path = file_path.to_owned() + "_proof.txt";
                println!("{}", output_path);
                self.build_pf_stat.proof_string = read_to_string(output_path).unwrap();
            }
            else {
                self.build_pf_stat.status = Some("Could not make proof file.".to_string());
                self.build_pf_stat.proof_verified = false;
                self.build_pf_stat.proof_reason = Some(reason);
            }
        }
    }

    fn build_valid(&mut self) -> bool {

        let mut corpus_valid = false;
        if self.build_ts_stat.hashes {
            if self.build_ts_stat.hash_file.is_none() {
                self.build_ts_stat.build_status = Some("You must select a hash file.".to_string());
            }
            else {
                self.session.hashes_path = self.build_ts_stat.hash_file.clone();
                corpus_valid = true;
            }
        }
        else if !self.build_ts_stat.hashes {
            if self.build_ts_stat.directory.is_none() {
                self.build_ts_stat.build_status = Some("You must select a directory.".to_string());
            }
            else {
                self.session.source_dir_path = self.build_ts_stat.directory.clone();
                corpus_valid = true;
            }
        }

        let inputs_valid = self.build_ts_stat.corpus_name != "".to_string() &&
                                    self.build_ts_stat.identifier != "".to_string() &&
                                    self.build_ts_stat.output_dir.is_some();

        corpus_valid && inputs_valid
    }

    fn build_timestamp(&mut self) {
        let mut valid = false;
        if self.build_ts_stat.hashes {
            if self.build_ts_stat.hash_file.is_none() {
                self.build_ts_stat.build_status = Some("You must select a hash file.".to_string());
            }
            else {
                self.session.hashes_path = self.build_ts_stat.hash_file.clone();
                self.build_ts_stat.build_status = None;
                valid = true;
            }
        }
        else if !self.build_ts_stat.hashes {
            if self.build_ts_stat.directory.is_none() {
                self.build_ts_stat.build_status = Some("You must select a directory.".to_string());
            }
            else {
                self.session.source_dir_path = self.build_ts_stat.directory.clone();
                self.build_ts_stat.build_status = None;
                valid = true;
            }
        }

        if valid {
            self.build_ts_stat.build_attempted = true;
            self.session.timestamp_output_path = self.build_ts_stat.output_dir.clone();
            let (succeeded, reason) = self.session.build_timestamp(&self.build_ts_stat.corpus_name, &self.build_ts_stat.identifier, self.build_ts_stat.hashes, self.build_ts_stat.corpus_desc.clone(), self.build_ts_stat.corpus_motiv.clone(), self.build_ts_stat.user_desc.clone());
            if succeeded {
                self.build_ts_stat.root_hash = Some(format!("{}", HexFmt(self.session.uftree.as_ref().unwrap().get_root_hash())));
                self.build_ts_stat.num_leaves = Some(self.session.uftree.as_ref().unwrap().num_leaves);
                self.build_ts_stat.tree_exists = true;
                self.build_ts_stat.tree_file = self.session.tree_filename.clone();
                self.build_ts_stat.explain_file = self.session.explain_filename.clone();
                let explain_path = self.build_ts_stat.explain_file.as_ref().unwrap();
                self.build_ts_stat.explain_string = std::fs::read_to_string(explain_path).unwrap();
                let tag_path = self.session.tag_filename.as_ref().unwrap();
                self.build_ts_stat.tag_string = std::fs::read_to_string(tag_path).unwrap();
            }
            else {
                self.build_ts_stat.tree_exists = false;
                self.build_ts_stat.build_status = Some(format!("The build failed for the following reason: {}", reason));
            }
        }
    }

    fn examine_explain_file(&mut self, ui: &mut egui::Ui) {
        let ten_lines = 20.0 * ui.text_style_height(&egui::TextStyle::Body);

        egui::ScrollArea::vertical()
            .max_height(ten_lines)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.build_ts_stat.explain_string)
                        .desired_width(f32::INFINITY)
                        .desired_rows(20)
                        .interactive(false),
                );
            });
    }

    fn finalize_timestamp(&mut self) {        
        self.build_ts_stat.tree_file = self.session.tree_filename.clone();
        self.build_ts_stat.explain_file = self.session.explain_filename.clone();
        let tree_path_buf = self.build_ts_stat.tree_file.as_ref().unwrap();
        let tree_path = tree_path_buf.to_str().unwrap();
        let explain_path_buf = self.build_ts_stat.explain_file.as_ref().unwrap();
        let explain_path = explain_path_buf.to_str().unwrap();

        let (tx_hash_option, reason) = Session::parse_hash(&self.build_ts_stat.tx_hash_string);

        if tx_hash_option.is_none() {
            self.build_ts_stat.finalize_status = Some(format!("The process failed for the following reason: {}", reason));
            self.build_ts_stat.tree_verified_reason = Some(reason);
        }

        else {
            let tx_hash = tx_hash_option.unwrap();
            let (result, reason) = self.session.finalize_timestamp(tree_path, explain_path, &self.build_ts_stat.corpus_name, &self.build_ts_stat.identifier, tx_hash);

            self.build_ts_stat.tree_verified = result;
            self.build_ts_stat.tree_verified_reason = Some(reason);

            if result {
                self.build_ts_stat.finalize_status = Some(format!("Timestamp verified on the blockchain! \nTimestamped merkle tree file written to {}", tree_path));
            }
            else {
                self.build_ts_stat.finalize_status = Some("The timestamp failed to verify on the blockchain.".to_string());
            }  
        }


    }

    fn page_welcome(&mut self, ui: &mut egui::Ui) {
        ui.heading("Welcome");
        ui.label("This is a prototype GUI for Amber, still in active development. Use at your own risk.");

        ui.horizontal(|ui| {
            if ui.button("Tell me what's going on").clicked() {
                self.jump_to(Page::Explanation);
            }

            if ui.button("I know what I'm doing").clicked() {
                self.jump_to(Page::Functions);
            }
        });

    }

    fn page_explanations(&mut self, ui: &mut egui::Ui) {
        ui.heading("What is Amber?");
        let amber_description= "Amber is a tool for creating and working with secure timestamps. A secure timestamp is a digital artifact that provides cryptographic-level proof that some data existed at a certain date and time. An Amber-produced secure timestamp typically attests to the existence of a corpus of digital files, but can also be used to create secure timestamp proofs of single files.";
        ui.label(amber_description);

        //let placeholder = "Things to add here:\n  - explain components of secure timestamp\n  - explain how the blockchain message proves that the data existed at a certain time\n  - explain proof files";
        //ui.label(placeholder);

        let more_info = " For more information see the README at";
        ui.horizontal(|ui| {
            ui.label(more_info);
            ui.hyperlink_to("the Amber github repo,", "https://www.github.com/tenchd/amber/");
        });

        let more_more_info = " or read the project overview on";
        ui.horizontal(|ui| {
            ui.label(more_more_info);
            ui.hyperlink_to("my personal website.", "https://www.davidtench.com/timestamp_overview");
        });

        if ui.button("Back to welcome page").clicked(){
            self.jump_to(Page::Welcome);
        }
    }

    fn page_list_functions(&mut self, ui: &mut egui::Ui) {

        ui.heading("Functionality");
        //ui.label("If you have a secure timestamp produced by Amber, you can use this tool to verify it and use it to authenticate files. It can also authenticate single-file timestamp proofs. It can also create new single-file timestamp proofs from a secure timestamp. Finally, you can use it to create a new secure timestamp from a corpus of files.");

        let gap = 12.0;
        let available = ui.available_width();
        let cell_width = ((available - gap) / 2.0).max(0.0);
        let buttons = [
            ("Verify files", "Verify files using an existing secure timestamp"),
            ("Verify file", "Verify a file using a single-file proof"),
            ("Create timestamp", "Create a new secure timestamp"),
            ("Create a proof", "Create a proof for a single file"),
        ];

        egui::Grid::new("button_grid")
        .num_columns(2)
        .spacing([gap, gap])
        .show(ui, |ui| {
            for (i, (button_text, description)) in buttons.iter().enumerate() {
                ui.allocate_ui_with_layout(
                    egui::vec2(cell_width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |cell_ui| {
                        cell_ui.label(*description);
                        let target; 

                        if cell_ui
                            .add( egui::Button::new(*button_text))
                            .clicked()
                        {
                            match i {
                                0 => {target = Page::VerifyTreeAndFile;}
                                1 => {target = Page::VerifyProof;}
                                2 => {target = Page::WelcomeTimestamp;}
                                3 => {target = Page::BuildProof;}
                                _ => unreachable!(),
                            }
                            self.jump_to(target);
                        }
                    },
                );

                if i % 2 == 1 {
                    ui.end_row();
                }
            }
        });

        ui.label("");
        ui.separator();

        if ui.button("Back to welcome page").clicked() {
            self.jump_to(Page::Welcome);
        }
    }

    fn page_verify_tree_and_file(&mut self, ui: &mut egui::Ui) {
        if self.ver_stat.async_running {
            self.finish_verify();
        }

        ui.heading("Verify Files with a Secure Timestamp");

        ui.label("An Amber secure timestamp consists of");

        ui.label("- an explanatory text file (usually called something like explain.txt)");
        ui.label("- a Merkle tree file (usually called something like merkle.txt)");
        ui.label("- a message on the Bitcoin blockchain serving as a time-witness of the merkle tree and explain.txt");
        ui.label("- a corpus of files that the Merkle tree encodes");
        ui.label("To verify a timestamp, you must find the blockchain message and confirm that it witnesses the Merkle tree and explain.txt. Then you can use the Merkle to confirm that files from the corpus existed at the stated date and time.");
        ui.label("This page automates that process.");

        ui.separator();

        ui.heading("Step 1: Load and verify a secure timestamp");
        ui.label("Select the merkle tree file and explanatory file for the timestamp you want to verify.");

        egui::Grid::new("verify_options").show(ui, |ui| {
            ui.vertical(|ui|{

                ui.horizontal(|ui|{
                    //if ui.button("Pick merkle file").clicked() {
                    if ui.add_enabled(!self.ver_stat.verify_attempted, egui::Button::new("Pick Merkle file")).clicked() {
                        self.ver_stat.provided_merkle_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.ver_stat.provided_merkle_file.is_some(){
                        ui.label(format!("Merkle file: \n{:?}", self.ver_stat.provided_merkle_file.clone().unwrap()));
                    }
                });

                self.ver_stat.provided_merkle_file_dialog.update(ui);
                if let Some(path) = self.ver_stat.provided_merkle_file_dialog.take_picked() {
                    self.ver_stat.provided_merkle_file = Some(path.to_path_buf());
                }
            });

            ui.vertical(|ui|{
                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.ver_stat.verify_attempted, egui::Button::new("Pick explain file")).clicked() {
                        self.ver_stat.provided_explain_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.ver_stat.provided_explain_file.is_some(){
                        ui.label(format!("Explain file: \n{:?}", self.ver_stat.provided_explain_file.clone().unwrap()));
                    }
                });
                self.ver_stat.provided_explain_file_dialog.update(ui);
                if let Some(path) = self.ver_stat.provided_explain_file_dialog.take_picked() {
                    self.ver_stat.provided_explain_file = Some(path.to_path_buf());
                }
            });
        });
        
        if ui.add_enabled(!self.ver_stat.verify_attempted && !self.ver_stat.async_running && self.ver_stat.provided_merkle_file.is_some() && self.ver_stat.provided_explain_file.is_some(), egui::Button::new("Verify timestamp")).clicked() {
            self.ver_stat.clear_verify_state();
            self.start_verify();
        }        
        
        if self.ver_stat.async_running {
            ui.spinner();
            ui.label("Verifying timestamp on the blockchain...");
        }
        
        if self.ver_stat.verified.is_some() {
            ui.label(format!("Verified: {}", self.ver_stat.verified.clone().unwrap()));

            if self.ver_stat.verified.unwrap() {
                if self.ver_stat.reason.as_ref().unwrap() != &FailureReason::Success {
                    ui.label("WARNING: while the verification succeeded, the following warning was emitted:");
                    ui.label(format!("{}", self.ver_stat.reason.as_ref().unwrap()));
                }
                let (date, time) = convert_utc_to_datetime(self.ver_stat.utc.clone().unwrap());
                ui.label(format!("Corpus identifier: {}", self.ver_stat.tree.as_ref().unwrap().identifier));
                ui.label(format!("Date: {}", date));
                ui.label(format!("Time: {} UTC", time));
                if !self.ver_stat.show_more {
                    if ui.button("Show more information").clicked() {
                        self.ver_stat.show_more = true;
                    }
                }
                else {
                    if ui.button("Show less information").clicked() {
                        self.ver_stat.show_more = false;
                    }

                    ui.label(format!("tx hash: {}", self.ver_stat.tx_hash.clone().unwrap()));
                    ui.label(format!("block: {}", self.ver_stat.block.clone().unwrap()));
                    ui.label(format!("UTC epoch of blockchain transaction: {}", self.ver_stat.utc.clone().unwrap()));
                }
            }
            else {
                ui.label("The verification failed for the following reason:");
                ui.label(format!("{}", self.ver_stat.reason.as_ref().unwrap()));
            }
        }

        ui.label("");
        if self.ver_stat.verify_attempted && !self.ver_stat.async_running {
            if ui.button("Verify a different timestamp").clicked() {
                self.ver_stat = VerificationStatus::new();
                self.auth_stat = AuthenticationStatus::new();
            }
        }

        ui.separator();

        if self.ver_stat.verified.is_some() && self.ver_stat.verified.unwrap() {
            ui.heading("Step 2: Authenticate a file with the verified timestamp");
            ui.label("The timestamp is loaded and verified. You can now use it to authenticate files from the timestamped corpus.");
            ui.label("Choose a file to authenticate:");

            //if ui.button("Choose file").clicked() {
            if ui.add_enabled(!self.auth_stat.auth_attempted, egui::Button::new("Choose file")).clicked() {
                self.auth_stat.provided_file_dialog.pick_file();
            }
            if self.auth_stat.provided_file.is_some(){
                ui.label(format!("File to authenticate: {:?}", self.auth_stat.provided_file.clone().unwrap()));
                //if ui.button("Authenticate file").clicked() {
                if ui.add_enabled(!self.auth_stat.auth_attempted, egui::Button::new("Authenticate file")).clicked() {
                    self.auth_stat.clear_auth_state();
                    self.authenticate_file();
                }

                if self.auth_stat.file_auth_status.is_some() {
                    ui.label(format!("{}", self.auth_stat.file_auth_status.clone().unwrap()));
                }

                if self.auth_stat.file_authenticated.is_some() {
                    if self.auth_stat.file_authenticated.unwrap() {
                        let (date, time) = convert_utc_to_datetime(self.ver_stat.utc.clone().unwrap());
                        ui.label(format!("AUTHENTICATED. The file existed on {} at {}.", date, time));
                    }

                    else {
                        ui.label("NOT AUTHENTICATED. Cannot confirm when the file existed.");
                    }

                    if ui.button("Authenticate another file").clicked() {
                        self.auth_stat = AuthenticationStatus::new();
                    }
                }
            }
            self.auth_stat.provided_file_dialog.update(ui);
            if let Some(path) = self.auth_stat.provided_file_dialog.take_picked() {
                self.auth_stat.provided_file = Some(path.to_path_buf());
            }


            ui.separator();
        }


        if ui.button("Back").clicked() {
            self.jump_to(Page::Functions);
        }
    }

    fn page_verify_proof(&mut self, ui: &mut egui::Ui) {
        ui.heading("Verify a Merkle proof");

        ui.label("Amber can produce small 'proofs' for single files that are part of a large timestamped corpus. The `proof` establishes that the corpus file existed at the time the secure timestamp was produced.");
        ui.label("This page allows you to use an existing proof file to verify that its corresponding corpus file existed at the time of the timestamp's creation.");

        egui::Grid::new("verify_options").show(ui, |ui| {
            ui.vertical(|ui|{

                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.proof_stat.proof_auth_attempted, egui::Button::new("Pick proof file")).clicked() {
                        self.proof_stat.provided_proof_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.proof_stat.provided_proof_file.is_some(){
                        ui.label(format!("Proof file: {:?}", self.proof_stat.provided_proof_file.clone().unwrap()));
                    }
                });

                self.proof_stat.provided_proof_file_dialog.update(ui);
                if let Some(path) = self.proof_stat.provided_proof_file_dialog.take_picked() {
                    self.proof_stat.provided_proof_file = Some(path.to_path_buf());
                }
            });

            ui.vertical(|ui|{
                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.proof_stat.proof_auth_attempted, egui::Button::new("Pick corpus file to verify")).clicked() {
                        self.proof_stat.provided_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.proof_stat.provided_file.is_some(){
                        ui.label(format!("File: {:?}", self.proof_stat.provided_file.clone().unwrap()));
                    }
                });
                self.proof_stat.provided_file_dialog.update(ui);
                if let Some(path) = self.proof_stat.provided_file_dialog.take_picked() {
                    self.proof_stat.provided_file = Some(path.to_path_buf());
                }
            });
        });

        if self.proof_stat.provided_file.is_some() && self.proof_stat.provided_proof_file.is_some() {
            if ui.add_enabled(!self.proof_stat.proof_auth_attempted, egui::Button::new("Verify proof")).clicked() {
                self.verify_proof();
            }
        }

        if self.proof_stat.proof_auth_status.is_some() {
            ui.label(format!("{}", self.proof_stat.proof_auth_status.clone().unwrap()));
        }

        if self.proof_stat.proof_authenticated.is_some() {
            ui.label(format!("Verified: {}", self.proof_stat.proof_authenticated.unwrap()));
            if self.proof_stat.proof_authenticated.unwrap() {
                ui.label(format!("{}", self.proof_stat.proof_auth_reason.as_ref().unwrap()));
                ui.label(format!("Corpus identifier: {}", self.proof_stat.proof_id.clone().unwrap()));
                ui.label(format!("Date: {}", self.proof_stat.proof_date.clone().unwrap()));
                ui.label(format!("Time: {}", self.proof_stat.proof_time.clone().unwrap()));

                if !self.proof_stat.show_more {
                    if ui.button("Show more information").clicked() {
                        self.proof_stat.show_more = true;
                    }
                }
                else {
                    if ui.button("Show less information").clicked() {
                        self.proof_stat.show_more = false;
                    }

                    ui.label(format!("tx hash: {}", self.proof_stat.proof_tx_hash.clone().unwrap()));
                    ui.label(format!("block: {}", self.proof_stat.proof_block.clone().unwrap()));
                    ui.label(format!("UTC epoch: {}", self.proof_stat.proof_utc.clone().unwrap()));
                }
            }
            else {
                ui.label("The proof failed to verify for the following reason:");
                ui.label(format!("{}", self.proof_stat.proof_auth_reason.as_ref().unwrap()));
            }

            if ui.button("Verify a different proof").clicked() {
                self.proof_stat = ProofStatus::new();
            }
        }

        ui.separator();

        if ui.button("Back").clicked() {
            self.jump_to(Page::Functions);
        }
    }

    fn page_build_proof(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create a Merkle proof file");

        ui.label("Using an existing secure timestamp of a corpus, Amber can produce a small 'proof' of a single file in the corpus. The proof file serves as a secure timestamp for that specific corpus file only. The advantage of this is that the proof file is much smaller than the whole secure timestamp.");

        ui.label("This page lets you create a proof for a specific file from an already-timestamped corpus.");

        egui::Grid::new("verify_options").show(ui, |ui| {
            ui.vertical(|ui|{

                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.build_pf_stat.proof_attempted, egui::Button::new("Pick Merkle file")).clicked() {
                        self.build_pf_stat.merkle_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.build_pf_stat.merkle_file.is_some() {
                        ui.label(format!("File: {:?}", self.build_pf_stat.merkle_file.clone().unwrap()));
                    }
                });
                self.build_pf_stat.merkle_file_dialog.update(ui);
                if let Some(path) = self.build_pf_stat.merkle_file_dialog.take_picked() {
                    self.build_pf_stat.merkle_file = Some(path.to_path_buf());
                }
            });

            ui.vertical(|ui|{

                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.build_pf_stat.proof_attempted, egui::Button::new("Pick explain file")).clicked() {
                        self.build_pf_stat.explain_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.build_pf_stat.explain_file.is_some() {
                        ui.label(format!("File: {:?}", self.build_pf_stat.explain_file.clone().unwrap()));
                    }
                });
                self.build_pf_stat.explain_file_dialog.update(ui);
                if let Some(path) = self.build_pf_stat.explain_file_dialog.take_picked() {
                    self.build_pf_stat.explain_file = Some(path.to_path_buf());
                }
            });

            ui.end_row();

            ui.vertical(|ui|{
                ui.horizontal(|ui|{
                    if ui.add_enabled(!self.build_pf_stat.proof_attempted, egui::Button::new("Pick file to create proof for")).clicked() {
                        self.build_pf_stat.proven_file_dialog.pick_file();
                    }
                });

                ui.horizontal(|ui|{
                    if self.build_pf_stat.proven_file.is_some(){
                        ui.label(format!("File: {:?}", self.build_pf_stat.proven_file.clone().unwrap()));
                    }
                    self.build_pf_stat.proven_file_dialog.update(ui);
                    if let Some(path) = self.build_pf_stat.proven_file_dialog.take_picked() {
                        self.build_pf_stat.proven_file = Some(path.to_path_buf());
                    }
                });
            });
        });
        
        ui.label("Enter the name of the timestamped corpus here:");
        ui.add_enabled(!self.build_pf_stat.proof_attempted, egui::TextEdit::singleline(&mut self.build_pf_stat.corpus_name));
        if self.build_pf_stat.corpus_name != "".to_string() {
            ui.label(format!("Corpus name will be listed as: \"{}\" in the proof file.", &self.build_pf_stat.corpus_name));
        }

        if self.build_pf_stat.corpus_name != "".to_string() && self.build_pf_stat.proven_file.is_some() && self.build_pf_stat.merkle_file.is_some() {
            if ui.add_enabled(!self.build_pf_stat.proof_attempted, egui::Button::new("Create proof")).clicked() {
                self.build_proof();
            }
        }

        if self.build_pf_stat.proof_verified {
            ui.label(format!("Proof successfully verified and written to {}_proof.txt", self.build_pf_stat.proven_file.as_ref().unwrap().to_str().unwrap()));

            ui.label("Here's a preview of the proof file you just made:");
            let ten_lines = 10.0 * ui.text_style_height(&egui::TextStyle::Body);

            egui::ScrollArea::vertical()
                .max_height(ten_lines)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.build_pf_stat.proof_string)
                            .desired_width(f32::INFINITY)
                            .desired_rows(10)
                            .interactive(false),
                    );
                });

            if ui.button("Create another proof").clicked() {
                self.build_pf_stat = BuildProofStatus::new();
            }
        }

        else {
            if self.build_pf_stat.proof_attempted {
                ui.label(format!("The proof build did not succeed for the following reason: {}", self.build_pf_stat.proof_reason.as_ref().unwrap()));
                if ui.button("Try again").clicked() {
                    self.build_pf_stat = BuildProofStatus::new();
                }
            }
        }

        ui.separator();
        
        if ui.button("Back").clicked() {
            self.jump_to(Page::Functions);
        }
    }

    fn page_welcome_timestamp(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create a New Secure Timestamp");

        ui.label("This page will guide you through the process of creating a secure timestamp of a collection of files (or \"corpus\"), and automate most of the creation process for you. This guide assumes that you know what secure timestamps are, why they are useful, and their limitations.");

        ui.heading("Before You Begin");
        ui.label("Before beginning this guide, you must:");
        ui.label("1. Think carefully about what you are timestamping, and why. Where did you acquire this data? Why do you wish to preserve it? How certain are you of its authenticity or usefulness? Exercise judgment and caution. Timestamping data sends a message to our descendants that you feel the data is valuable and accurate. Make every effort to avoid timestamping data that could be false or misleading.");
        ui.label("There is no principled way to prevent a user from maliciously timestamping untrustworthy data. I simply must ask you not to do so. To continue, check the box below promising that you will only timestamp data that you believe to be authentic and valuable.");
        ui.checkbox(&mut self.build_ts_stat.scouts_honor, "I promise to timestamp responsibly.");
        ui.label("2. Collect the files you wish to timestamp (and only those files) into a directory. The files can be distributed arbitrarily among subdirectories; the timestamp creation code will search the top-level directory recursively.");
        ui.label("3. Have a Bitcoin wallet containing some Bitcoin (a few USD's worth is more than enough). Further, your wallet software should be capable of submitting a blockchain transaction containing a custom OP_RETURN script. If you don't know what that means, I recommend you install the Electrum open-source Bitcoin wallet.");
        ui.hyperlink_to("Electrum bitcoin wallet", "https://electrum.org/");
        ui.label("We will use the bitcoin wallet during the timestamping process to write a small amount of timestamp data permanently to the Bitcoin blockchain. This is a crucial part of the timestamping process and cannot be skipped. I provide detailed instructions later in this guide for accomplishing this step using Electrum.");


        ui.separator();

        if ui.add_enabled(self.build_ts_stat.scouts_honor, egui::Button::new("Continue")).clicked() {
            self.jump_to(Page::OverviewTimestamp);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::Functions);
        }
    }

    fn page_overview_timestamp(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Building a Preliminary Timestamp");
        ui.label("The next few pages will guide you through the process of building the Merkle tree and generating explain.txt.");
        ui.heading("Overview of Timestamp Creation Process");

        ui.label("This guide will show you how to create a secure timestamp in three steps:\n
        1. Generating the Merkle tree and writing the explain.txt file. This also produces the short timestamp message to be written to the blockchain.\n
        2. Writing the timestamp message to the Bitcoin blockchain.\n
        3. After the blockchain transaction is accepted, writing the transaction hash to the Merkle tree file header.");
        ui.label("This program automates steps 1 and 3. You must do step 2 yourself, though I provide detailed instructions for how to do it.");

        ui.separator();

        if ui.button("Continue").clicked() {
            self.jump_to(Page::CorpusDesc);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::WelcomeTimestamp);
        }
    }

    fn page_corpus_desc(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Building a Preliminary Timestamp");
        ui.label("The next few pages will guide you through the process of building the Merkle tree and generating explain.txt.");
        ui.heading("Set Corpus Description");
        ui.label("Explain.txt will contain a short description below of the corpus you will timestamp. I recommend you address:\n
            i. the source(s) of the texts in the corpus\n
            ii.  the structure of the corpus. Is each text represented as its own file? If so, what formats are those files in? If not, how are texts represented (e.g., a text is a line of a csv file)?\n
            iii. any modifications you made to the texts before timestamping. Are they presented exactly as you found them? Did you clean up formatting or presentation, or add relevant metadata? Did you translate them into a different language? Etc. ");
        ui.label("");

        ui.label("You can either select a .txt file containing the corpus description, or write/paste it below.");

        let mut clicked = false;
        ui.horizontal(|ui| {
            clicked |= ui.radio_value(&mut self.build_ts_stat.corpus_desc_source, false, "Upload a .txt file").clicked();
            clicked |= ui.radio_value(&mut self.build_ts_stat.corpus_desc_source, true, "Enter manually").clicked();
        });

        if clicked {
            self.build_ts_stat.reset_corpus_desc_state();
        }

        if self.build_ts_stat.corpus_desc_source {

            let ten_lines = 20.0 * ui.text_style_height(&egui::TextStyle::Body);

            egui::ScrollArea::vertical()
                .max_height(ten_lines)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.build_ts_stat.corpus_desc)
                            .desired_width(f32::INFINITY)
                            .desired_rows(20)
                            .interactive(true),
                    );
                });
        }

        else {
            ui.horizontal(|ui|{
                if ui.button("Pick corpus description .txt file").clicked() {
                    self.build_ts_stat.corpus_desc_dialog.pick_file();
                }
            });

            ui.horizontal(|ui|{
                if self.build_ts_stat.corpus_desc_file.is_some() {
                    ui.label(format!("File: {:?}", self.build_ts_stat.corpus_desc_file.clone().unwrap()));
                }
            });
            self.build_ts_stat.corpus_desc_dialog.update(ui);
            if let Some(path) = self.build_ts_stat.corpus_desc_dialog.take_picked() {
                self.build_ts_stat.corpus_desc_file = Some(path.to_path_buf());
                self.build_ts_stat.corpus_desc = read_to_string(self.build_ts_stat.corpus_desc_file.clone().unwrap()).unwrap();
            }
            if self.build_ts_stat.corpus_desc != "".to_string() {

                ui.label("Here's a preview of the file you uploaded:");
                let ten_lines = 10.0 * ui.text_style_height(&egui::TextStyle::Body);

                egui::ScrollArea::vertical()
                    .max_height(ten_lines)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.build_ts_stat.corpus_desc)
                                .desired_width(f32::INFINITY)
                                .desired_rows(10)
                                .interactive(false),
                        );
                    });
            }
        }

        ui.separator();

        if ui.add_enabled(self.build_ts_stat.corpus_desc != "".to_string(), egui::Button::new("Continue")).clicked() {
            self.jump_to(Page::CorpusMotiv);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::OverviewTimestamp);
        }
    }

    fn page_corpus_motiv(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Building a Preliminary Timestamp");
        ui.label("The next few pages will guide you through the process of building the Merkle tree and generating explain.txt.");
        ui.heading("Set Corpus Motivation");
        ui.label("Write below a short explanation for why you are timestamping this corpus. Why do you feel it might be valuable to preserve?");
        ui.label("");

        ui.label("You can either select a .txt file containing the corpus motivation, or write/paste it below.");

        let mut clicked = false;
        ui.horizontal(|ui| {
            clicked |= ui.radio_value(&mut self.build_ts_stat.corpus_motiv_source, false, "Upload a .txt file").clicked();
            clicked |= ui.radio_value(&mut self.build_ts_stat.corpus_motiv_source, true, "Enter manually").clicked();
        });

        if clicked {
            self.build_ts_stat.reset_corpus_motiv_state();
        }

        if self.build_ts_stat.corpus_motiv_source {

            let ten_lines = 20.0 * ui.text_style_height(&egui::TextStyle::Body);

            egui::ScrollArea::vertical()
                .max_height(ten_lines)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.build_ts_stat.corpus_motiv)
                            .desired_width(f32::INFINITY)
                            .desired_rows(20)
                            .interactive(true),
                    );
                });
        }

        else {
            ui.horizontal(|ui|{
                if ui.button("Pick corpus description .txt file").clicked() {
                    self.build_ts_stat.corpus_motiv_dialog.pick_file();
                }
            });

            ui.horizontal(|ui|{
                if self.build_ts_stat.corpus_motiv_file.is_some() {
                    ui.label(format!("File: {:?}", self.build_ts_stat.corpus_motiv_file.clone().unwrap()));
                }
            });
            self.build_ts_stat.corpus_motiv_dialog.update(ui);
            if let Some(path) = self.build_ts_stat.corpus_motiv_dialog.take_picked() {
                self.build_ts_stat.corpus_motiv_file = Some(path.to_path_buf());
                self.build_ts_stat.corpus_motiv = read_to_string(self.build_ts_stat.corpus_motiv_file.clone().unwrap()).unwrap();
            }
            if self.build_ts_stat.corpus_motiv != "".to_string() {

                ui.label("Here's a preview of the file you uploaded:");
                let ten_lines = 10.0 * ui.text_style_height(&egui::TextStyle::Body);

                egui::ScrollArea::vertical()
                    .max_height(ten_lines)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.build_ts_stat.corpus_motiv)
                                .desired_width(f32::INFINITY)
                                .desired_rows(10)
                                .interactive(false),
                        );
                    });
            }
        }

        if ui.add_enabled(self.build_ts_stat.corpus_motiv != "".to_string(), egui::Button::new("Continue")).clicked() {
            self.jump_to(Page::UserDesc);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::CorpusDesc);
        }
    }

    fn page_user_desc(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 1: Building a Preliminary Timestamp");
        ui.label("The next few pages will guide you through the process of building the Merkle tree and generating explain.txt.");
        ui.heading("Set User Description");
        ui.label("Write below a short description of you, the person or organization creating the timestamp.");
        ui.label("OPTIONAL: If you like, you can use this field to establish your identity cryptographically.");
        if ui.button("Show crypto signing instructions").clicked(){
            self.build_ts_stat.show_signing = !self.build_ts_stat.show_signing;
        }

        if self.build_ts_stat.show_signing {
            ui.label("After writing a short description of yourself below, paste your public key. Then use your private key to sign a message containing your name, the merkle tree root hash, the corpus name, and the date. Include both the plaintext message and the signature (but of course not your private key). For longevity, I recommend using a post-quantum signing algorithm such as SLH-DSA.");
        }

        ui.label("");
        
        let mut clicked = false;
        ui.horizontal(|ui| {
            clicked |= ui.radio_value(&mut self.build_ts_stat.user_desc_source, false, "Upload a .txt file").clicked();
            clicked |= ui.radio_value(&mut self.build_ts_stat.user_desc_source, true, "Enter manually").clicked();
        });

        if clicked {
            self.build_ts_stat.reset_user_desc_state();
        }

        if self.build_ts_stat.user_desc_source {

            let ten_lines = 20.0 * ui.text_style_height(&egui::TextStyle::Body);

            egui::ScrollArea::vertical()
                .max_height(ten_lines)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.build_ts_stat.user_desc)
                            .desired_width(f32::INFINITY)
                            .desired_rows(20)
                            .interactive(true),
                    );
                });
        }

        else {
            ui.horizontal(|ui|{
                if ui.button("Pick user description .txt file").clicked() {
                    self.build_ts_stat.user_desc_dialog.pick_file();
                }
            });

            ui.horizontal(|ui|{
                if self.build_ts_stat.user_desc_file.is_some() {
                    ui.label(format!("File: {:?}", self.build_ts_stat.user_desc_file.clone().unwrap()));
                }
            });
            self.build_ts_stat.user_desc_dialog.update(ui);
            if let Some(path) = self.build_ts_stat.user_desc_dialog.take_picked() {
                self.build_ts_stat.user_desc_file = Some(path.to_path_buf());
                self.build_ts_stat.user_desc = read_to_string(self.build_ts_stat.user_desc_file.clone().unwrap()).unwrap();
            }
            if self.build_ts_stat.user_desc != "".to_string() {

                ui.label("Here's a preview of the file you uploaded:");
                let ten_lines = 10.0 * ui.text_style_height(&egui::TextStyle::Body);

                egui::ScrollArea::vertical()
                    .max_height(ten_lines)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.build_ts_stat.user_desc)
                                .desired_width(f32::INFINITY)
                                .desired_rows(10)
                                .interactive(false),
                        );
                    });
            }
        }

        if ui.add_enabled(self.build_ts_stat.user_desc != "".to_string(), egui::Button::new("Continue")).clicked() {
            self.jump_to(Page::BuildTimestamp);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::CorpusMotiv);
        }
    }

    fn page_build_timestamp(&mut self, ui: &mut egui::Ui) {

        ui.heading("Step 1: Building a Preliminary Timestamp");
        ui.label("The next few pages will guide you through the process of building the Merkle tree and generating explain.txt.");

        ui.heading("Building the Merkle tree");
        ui.label("To build the Merkle tree, you need either a directory containing the files you want to timestamp, or a previously-computed leaf hashes file.");
        if ui.button("What is a leaf hashes file?").clicked() {
            self.build_ts_stat.hashes_explain = !self.build_ts_stat.hashes_explain;
        }

        if self.build_ts_stat.hashes_explain {
            ui.label("A leaf hashes file is a text file that contains a set of SHA256 hashes. If you have built a Merkle tree using this page before, the code also generated a file called \"leaf_hashes.txt\". Rebuilding the Merkle tree from this leaf hash file is often much faster than building the tree from the directory again.");
        }
    
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.build_ts_stat.hashes, false, "Directory");
            ui.radio_value(&mut self.build_ts_stat.hashes, true, "Hashes");
        });
        ui.end_row();

        if self.build_ts_stat.hashes {
            if ui.add_enabled(!self.build_ts_stat.build_attempted, egui::Button::new("Pick hash file")).clicked() {
                self.build_ts_stat.hash_file_dialog.pick_file();
            }
            if self.build_ts_stat.hash_file.is_some() {
                ui.label(format!("File: {:?}", self.build_ts_stat.hash_file.clone().unwrap()));
            }
            self.build_ts_stat.hash_file_dialog.update(ui);
            if let Some(path) = self.build_ts_stat.hash_file_dialog.take_picked() {
                self.build_ts_stat.hash_file = Some(path.to_path_buf());
            }
        }
        else {
            if ui.add_enabled(!self.build_ts_stat.build_attempted, egui::Button::new("Pick directory")).clicked() {
                self.build_ts_stat.directory_dialog.pick_directory();
            }
            if self.build_ts_stat.directory.is_some() {
                ui.label(format!("File: {:?}", self.build_ts_stat.directory.clone().unwrap()));
            }
            self.build_ts_stat.directory_dialog.update(ui);
            if let Some(path) = self.build_ts_stat.directory_dialog.take_picked() {
                self.build_ts_stat.directory = Some(path.to_path_buf());
            }
        }

        ui.separator();

        ui.label("Choose a short name for the corpus you are timestamping and write it below. For example, if the corpus was a collection of TIME Magazine articles from 2020 I might call the corpus \"TIME Magazine 2020\".");

        ui.label("Write the corpus name:");
        ui.add_enabled(!self.build_ts_stat.build_attempted, egui::TextEdit::singleline(&mut self.build_ts_stat.corpus_name));
        if self.build_ts_stat.corpus_name != "".to_string() {
            ui.label(format!("Corpus name will be listed as: \"{}\"", &self.build_ts_stat.corpus_name));
        }
        ui.separator();

        // ui.label("Look up the height of the most recent block on the Bitcoin blockchain. Enter that value plus two into the box below:");
        // ui.add(egui::DragValue::new(&mut self.build_ts_stat.locktime).speed(1.0));
        // ui.separator();

        ui.label("Choose an 8-character ASCII identifier for your corpus and enter it below. Make sure it is exactly 8 characters. Continuing the above example, I might choose the identifier \"TIMEMGZN\".");
        ui.label("Write the identifier:");
        ui.add_enabled(!self.build_ts_stat.build_attempted, egui::TextEdit::singleline(&mut self.build_ts_stat.identifier));
        if self.build_ts_stat.identifier != "".to_string() {
            ui.label(format!("Identifier will be listed as: \"{}\"", &self.build_ts_stat.identifier));
        }

        ui.separator();

        ui.label("Now select the location to write the timestamp files to.");
        if ui.add_enabled(!self.build_ts_stat.build_attempted, egui::Button::new("Pick location to write timestamp")).clicked() {
            self.build_ts_stat.output_dir_dialog.pick_directory();
        }
        if self.build_ts_stat.output_dir.is_some() {
            ui.label(format!("File: {:?}", self.build_ts_stat.output_dir.clone().unwrap()));
        }
        self.build_ts_stat.output_dir_dialog.update(ui);
        if let Some(path) = self.build_ts_stat.output_dir_dialog.take_picked() {
            self.build_ts_stat.output_dir = Some(path.to_path_buf());
        }

        ui.separator();

        if ui.add_enabled(self.build_valid() && !self.build_ts_stat.build_attempted, egui::Button::new("Build the timestamp")).clicked() {
            self.build_timestamp();
        }

        if self.build_ts_stat.build_status.is_some() && self.build_ts_stat.build_attempted {
            ui.label(self.build_ts_stat.build_status.as_ref().unwrap());
        }

        if self.build_ts_stat.build_attempted {
            if ui.button("Undo build and try again.").clicked() {
                self.build_ts_stat.reset_prelim_build_state();
            }
        }

        if self.build_ts_stat.tree_exists {
            ui.label(format!("Built merkle tree with {} leaves and root hash \n{}", self.build_ts_stat.num_leaves.unwrap(), self.build_ts_stat.root_hash.as_ref().unwrap()));

            if ui.button("Examine unfinalized timestamp").clicked() {
                self.ver_stat.clear_verify_state();
                self.jump_to(Page::ExamineExplain);
            }
        }

        ui.separator();

        if ui.button("Back").clicked() {
            self.jump_to(Page::UserDesc);
        }

    }

    fn page_examine_explain(&mut self, ui: &mut egui::Ui) {
        ui.heading("Checking the Unfinalized Timestamp");
        ui.label(format!("You just built a merkle tree with {} leaves and root hash \n{}", self.build_ts_stat.num_leaves.unwrap(), self.build_ts_stat.root_hash.as_ref().unwrap()));

        ui.label("In addition to creating the merkle tree, you just wrote explain.txt. Click the button below to examine it.");
        ui.label("Read it carefully and make sure everything is displayed correctly! The next step after this is to write to the blockchain, and after you do you cannot go back and edit explain.txt or the merkle tree.");



        if !self.build_ts_stat.show_explain {
            if ui.button("Show explain.txt").clicked(){
                self.build_ts_stat.show_explain = true;
                self.build_ts_stat.explain_shown = true;
            }
        }
        else {
            if ui.button("Hide explain.txt").clicked() {
                self.build_ts_stat.show_explain = false;
            }
        }

        if self.build_ts_stat.show_explain {
            self.examine_explain_file(ui);
        }
        ui.separator();

        if ui.add_enabled(self.build_ts_stat.explain_shown, egui::Button::new("Continue")).clicked() {
            self.jump_to(Page::WriteBlockchainMessage);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::BuildTimestamp);
        }
    }

    fn page_write_blockchain(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 2: Writing to the Bitcoin Blockchain");

        ui.label("You have created the merkle tree, whose root hash serves as a witness of existence for each file in the corpus.");
        ui.label("Now we are going to write that root hash, the hash of explain.txt, and a few other pieces of metadata to the Bitcoin blockchain.");
        ui.label("Doing this will inherently timestamp the data, since each Bitcoin transaction is automatically timestamped.");
        ui.label("");
        ui.label("To write to the blockchain, follow the instructions in this guide:");
        ui.hyperlink_to("OP_RETURN transaction guide",
            "https://planb.academy/en/tutorials/wallet/desktop/electrum-opreturn-46cd3701-cb52-4dda-8251-9fd10e8f8542");
        ui.label("In the above guide, use the following string as the hexadecimal message sent via OP_RETURN:");
        let text = &self.build_ts_stat.tag_string.clone();
        ui.horizontal(|ui| {

            //ui.label(text);
            let textbox_width = ui.available_width() - 30.0;
            ui.add(egui::TextEdit::multiline(&mut self.build_ts_stat.tag_string.clone()).interactive(false).desired_width(textbox_width));

            if ui.small_button("📋").on_hover_text("Copy to clipboard").clicked() {
                ui.ctx().copy_text(text.to_string());
            }
        });

        if !self.build_ts_stat.show_tag_explanation {
            if ui.button("What does this message mean?").clicked() {
                self.build_ts_stat.show_tag_explanation = true;
            }
        }
        else {
            if ui.button("Hide message explanation").clicked() {
                self.build_ts_stat.show_tag_explanation = false;
            }
            ui.label("This message string consists of:");

            ui.label(format!("- The 8-character identifier of your corpus ({}) in hex: {}", self.build_ts_stat.identifier, &text[0..16]));
            ui.label(format!("- The number of leaves in your merkle tree ({}) in hex: {}", self.build_ts_stat.num_leaves.unwrap(), &text[16..24]));
            ui.label(format!("- The root hash of the merkle tree in hex: {}", self.build_ts_stat.root_hash.as_ref().unwrap()));
            ui.label(format!("- The hash of explain.txt in hex: {}", &text[88..152]));

        }


        ui.label("");
        ui.label("By writing this string to the blockchain, you will prove that explain.txt and each file in the merkle tree existed today.");
        ui.label("Once you submit your blockchain transaction, wait for the network to confirm it. Once it is confirmed, note the transaction hash and click Continue below.");

        ui.separator();

        if ui.button("Continue").clicked() {
            self.jump_to(Page::FinalizeTimestamp);
        }

        if ui.button("Back").clicked() {
            self.jump_to(Page::ExamineExplain);
        }
    }

    fn page_finalize_timestamp(&mut self, ui: &mut egui::Ui) {
        ui.heading("Step 3: Finalizing the Timestamp");
        ui.label("On the previous page you submitted a transaction to the Bitcoin blockchain. Enter the hash of that transaction below:");
        ui.add_enabled(self.build_ts_stat.tree_verified_reason.is_none(), egui::TextEdit::singleline(&mut self.build_ts_stat.tx_hash_string));

        ui.label("Clicking the \"Finalize Timestamp\" button will look up the Bitcoin transaction on the blockchain and confirm that it contains the correct timestamp information. If it does, it will add some data to the Merkle tree file to enable automatic verification in the future.");

        if ui.add_enabled(self.build_ts_stat.tx_hash_string!="".to_string() && !self.build_ts_stat.tree_verified && self.build_ts_stat.tree_verified_reason.is_none(), egui::Button::new("Finalize timestamp")).clicked() {
            self.finalize_timestamp();
        }

        if self.build_ts_stat.finalize_status.is_some() {
            ui.label(self.build_ts_stat.finalize_status.clone().unwrap());

            if !self.build_ts_stat.tree_verified {
                ui.label("Something went wrong and the blockchain transaction could not be verified.");
                if ui.button("Retry").clicked() {
                    self.build_ts_stat.reset_finalize_state();
                }
            }
        }

        if self.build_ts_stat.tree_verified {
            ui.label(format!("Corpus identifier: {}", self.session.tstree.as_ref().unwrap().identifier));
            let (date, time) = convert_utc_to_datetime(self.session.tstree.as_ref().unwrap().utc_timestamp);
            ui.label(format!("Date: {}", date));
            ui.label(format!("Time: {} UTC", time));

            if !self.build_ts_stat.show_more {
                if ui.button("Show more information").clicked() {
                    self.build_ts_stat.show_more = true;
                }
            }
            else {
                if ui.button("Show less information").clicked() {
                    self.build_ts_stat.show_more = false;
                }
                ui.label(format!("tx hash: {}", HexFmt(self.session.tstree.as_ref().unwrap().tx_hash)));
                ui.label(format!("block height: {}", self.session.tstree.as_ref().unwrap().block_height));
                ui.label(format!("UTC epoch: {}", self.session.tstree.as_ref().unwrap().utc_timestamp));
            }

            ui.label("Click Continue for final instructions.");

            if ui.button("Continue").clicked() {
                self.jump_to(Page::Goodbye);
            }
        }
        if ui.add_enabled(!self.build_ts_stat.tree_verified, egui::Button::new("Back")).clicked() {
            self.jump_to(Page::WriteBlockchainMessage);
        }
    }

    fn page_goodbye(&mut self, ui: &mut egui::Ui) {
        ui.heading("Preserving Your Secure Timestamp");

        ui.label(format!("Congratulations! You have successfully created a secure timestamp of the {} corpus.",self.build_ts_stat.corpus_name));
        ui.label("It is important that you preserve the secure timestamp (merkle.txt and explain.txt), as well as the corpus files, exactly. Back them up in multiple locations and don't edit them in any way!");
        ui.label(format!("Merkle tree file: \n{}", self.session.tree_filename.as_ref().unwrap().to_str().unwrap()));
        ui.label(format!("Explanatory document: \n{}", self.session.explain_filename.as_ref().unwrap().to_str().unwrap()));

        if ui.button("Back to main page").clicked() {
            self.jump_to(Page::Functions);
        }
}
}

impl eframe::App for TemplateApp {
    /// Called by the framework to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Put your widgets into a `SidePanel`, `TopBottomPanel`, `CentralPanel`, `Window` or `Area`.
        // For inspiration and more examples, go to https://emilk.github.io/egui

        egui::Panel::top("top_panel").show(ui, |ui| {
            // The top panel is often a good place for a menu bar:

            egui::MenuBar::new().ui(ui, |ui| {
                // NOTE: no File->Quit on web pages!
                let is_web = cfg!(target_arch = "wasm32");
                if !is_web {
                    ui.menu_button("File", |ui| {
                        if ui.button("Quit").clicked() {
                            ui.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.add_space(16.0);
                }

                egui::widgets::global_theme_preference_buttons(ui);
            });
        });

        egui::Panel::bottom("bottom_panel").show(ui, |ui| {
            footer(ui);
        });


        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.page {
                    Page::Welcome => self.page_welcome(ui),
                    Page::Explanation => self.page_explanations(ui),
                    Page::Functions => self.page_list_functions(ui),
                    Page::VerifyTreeAndFile => self.page_verify_tree_and_file(ui),
                    Page::VerifyProof => self.page_verify_proof(ui),
                    Page::BuildProof => self.page_build_proof(ui),
                    Page::WelcomeTimestamp => self.page_welcome_timestamp(ui),
                    Page::OverviewTimestamp => self.page_overview_timestamp(ui),
                    Page::BuildTimestamp => self.page_build_timestamp(ui),
                    Page::CorpusDesc => self.page_corpus_desc(ui),
                    Page::CorpusMotiv => self.page_corpus_motiv(ui),
                    Page::UserDesc => self.page_user_desc(ui),
                    Page::ExamineExplain => self.page_examine_explain(ui),
                    Page::WriteBlockchainMessage => self.page_write_blockchain(ui),
                    Page::FinalizeTimestamp => self.page_finalize_timestamp(ui),
                    Page::Goodbye => self.page_goodbye(ui),
                    //_ => self.page_empty(ui),
                }
            });
        });
        
    }
}

fn footer(ui: &mut egui::Ui) {


    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        let space = 6.0;
        ui.add_space(space);

        ui.horizontal(|ui| {
            ui.add_space(space);
            powered_by_amber(ui);
            egui::warn_if_debug_build(ui);
        });

        ui.horizontal(|ui| {
            ui.add_space(space);
            ui.add(egui::github_link_file!(
                "https://github.com/tenchd/amber_gui/tree/main/",
                "Source code."
            ));
        });

        ui.separator();
    });
}

fn powered_by_amber(ui: &mut egui::Ui) {

    let (amber_version, amber_version_date) = amber_core::get_version_and_date();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Powered by ");
        ui.hyperlink_to("Amber ", "https://github.com/tenchd/amber");
        ui.label(format!("version {} released {}.", amber_version, amber_version_date));
    });
}


