use crate::app;
use crate::clock::{Clock, ClockReading, SystemClock};
use crate::vault_selector::{VaultAction, VaultSelector, VaultSelectorMode};
use chamber_import_export::{ExportFormat, export_items, import_items};
use chamber_password_gen::PasswordConfig;
use chamber_vault::{AutoLockConfig, Item, ItemKind, NewItem, Vault, VaultManager};
use color_eyre::Result;
use color_eyre::eyre::eyre;
use ratatui::prelude::Style;
use ratatui::style::Color;
use std::path::PathBuf;
use std::time::Duration;
use tui_textarea::TextArea;
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock,
    Main,
    AddItem,
    ViewItem,
    EditItem,
    ChangeMaster,
    GeneratePassword,
    ImportExport,
    VaultSelector,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnlockField {
    Master,
    Confirm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChangeKeyField {
    Current,
    New,
    Confirm,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AddItemField {
    Name,
    Kind,
    Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PasswordGenField {
    Length,
    Options,
    Generate,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ImportExportField {
    Path,
    Format,
    Action,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ImportExportMode {
    Export,
    Import,
}

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    All,
    Passwords,
    Environment,
    Notes,
}

impl ViewMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ViewMode::All => "Items",
            ViewMode::Passwords => "Passwords",
            ViewMode::Environment => "Environment",
            ViewMode::Notes => "Notes",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusType {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct ItemCounts {
    pub total: usize,
    pub passwords: usize,
    pub env_vars: usize,
    pub notes: usize,
    pub api_keys: usize,
    pub ssh_keys: usize,
    pub certificates: usize,
    pub databases: usize,
    pub credit_cards: usize,
    pub secure_notes: usize,
    pub identities: usize,
    pub servers: usize,
    pub wifi_passwords: usize,
    pub licenses: usize,
    pub bank_accounts: usize,
    pub documents: usize,
    pub recovery_codes: usize,
    pub oauth_tokens: usize,
}

#[derive(Debug, Clone)]
pub struct CountdownInfo {
    pub enabled: bool,
    pub minutes_left: i64,
    pub seconds_left: i64,
}

#[allow(clippy::struct_excessive_bools)]
pub struct App {
    clipboard: crate::clipboard::SessionClipboard,
    pub vault: Vault,
    pub vault_manager: VaultManager,
    pub vault_selector: VaultSelector,

    pub screen: Screen,
    pub master_input: String,
    pub master_confirm_input: String,
    pub master_mode_is_setup: bool,
    pub unlock_focus: UnlockField,
    pub error: Option<String>,

    pub items: Vec<Item>,
    pub selected: usize,
    pub view_mode: ViewMode,
    pub filtered_items: Vec<Item>,
    pub search_query: String,
    pub search_mode: bool,

    pub add_name: String,
    pub add_kind_idx: usize,
    pub add_value: String,
    pub add_value_scroll: usize,
    pub status_message: Option<String>,
    pub status_type: StatusType,
    pub scroll_offset: usize,
    pub add_value_textarea: TextArea<'static>,
    pub countdown_info: Option<CountdownInfo>,

    // Inactivity timer, owned by the event loop. Only `enabled` and `inactivity_timeout_minutes`
    // are read from the config.
    clock: Box<dyn Clock>,
    auto_lock_config: AutoLockConfig,
    /// Reading of the last activity while unlocked. `None` while locked or when auto-lock is disabled.
    last_activity: Option<ClockReading>,

    // Change passes key dialog fields
    pub ck_current: String,
    pub ck_new: String,
    pub ck_confirm: String,
    pub ck_focus: ChangeKeyField,
    pub add_focus: AddItemField,
    pub view_item: Option<Item>,
    pub view_show_value: bool,
    pub edit_item: Option<Item>,
    pub edit_value: String,

    // Password generation fields
    pub gen_focus: PasswordGenField,
    pub gen_length_str: String,
    pub gen_config: PasswordConfig,
    pub generated_password: Option<String>,

    // Import/Export fields
    pub ie_focus: ImportExportField,
    pub ie_mode: ImportExportMode,
    pub ie_path: String,
    pub ie_format_idx: usize,
    pub ie_formats: Vec<&'static str>,
}

impl App {
    /// Initializes a new instance of the struct.
    ///
    /// This function creates or opens a vault, determines whether the master mode setup
    /// is required, and initializes the various fields required for managing the application state.
    ///
    /// # Returns
    /// - `Result<Self>`: A `Result` containing the initialized struct instance on success,
    ///   or an error if the vault fails to open or create.
    ///
    /// # Fields
    /// - `vault`: Handles secure storage by opening or creating a vault.
    /// - `screen`: Represents the current active screen, initialized to the `Unlock` screen.
    /// - `master_input`: Stores user input for the master password during setup or unlock phase.
    /// - `master_confirm_input`: Stores user input for confirming the master password during setup.
    /// - `master_mode_is_setup`: Indicates whether the master mode is set up (false if initialization is incomplete).
    /// - `unlock_focus`: Tracks which unlock field is currently focused (e.g., Master field).
    /// - `error`: Holds any error message or state, defaulted to `None`.
    /// - `items`: A vector holding all items stored in the vault.
    /// - `selected`: Tracks the index of the currently selected item in the items list.
    /// - `view_mode`: Specifies the current filter/view mode for items (e.g., All items).
    /// - `filtered_items`: A vector holding the subset of items that match the current search query or filter.
    /// - `search_query`: Stores the user's current search input or query.
    /// - `add_name`: Field for the name of an item to be added.
    /// - `add_kind_idx`: Indicates the index of the kind/type of the item being added.
    /// - `add_value`: The value of the item being added.
    /// - `add_value_scroll`: Tracks the scroll state for long values when adding an item.
    /// - `status_message`: Holds transient status messages to display to the user.
    /// - `status_type`: Indicates the type of status message (e.g., Info, Warning, Error).
    ///
    /// # Change Key Fields
    /// - `ck_current`: Stores the current master key value.
    /// - `ck_new`: Stores the new master key value.
    /// - `ck_confirm`: Confirms the new master key value.
    /// - `ck_focus`: Tracks which field is focused during the change key process.
    ///
    /// # Add Item Fields
    /// - `add_focus`: Tracks which field is focused when adding a new item (e.g., Name).
    ///
    /// # Viewing and Editing Items
    /// - `view_item`: The currently selected item for viewing, if any.
    /// - `view_show_value`: Indicates whether to reveal the value of the viewed item.
    /// - `edit_item`: The item currently being edited, if any.
    /// - `edit_value`: The edited value of the currently selected item.
    ///
    /// # Password Generation
    /// - `gen_focus`: The current focus field in the password generation process (e.g., Length).
    /// - `gen_length_str`: String representation of the desired password length (default: "16").
    /// - `gen_config`: Configuration settings for password generation (e.g., character set, length).
    /// - `generated_password`: Holds the last generated password, if any.
    ///
    /// # Import/Export
    /// - `ie_focus`: Tracks which field is focused during import/export operations (e.g., File Path).
    /// - `ie_mode`: Indicates the mode (Import or Export) for import/export operations.
    /// - `ie_path`: Stores the file path selected for import/export.
    /// - `ie_format_idx`: Tracks the index of the currently selected format for import/export.
    /// - `ie_formats`: A vector containing supported file formats for import/export (e.g., "json", "csv").
    ///
    /// # Errors
    /// Return an error if the vault cannot be opened or created successfully.
    ///
    /// # Panics
    pub fn new() -> Result<Self> {
        let vault = Vault::open_default()?;
        let vault_manager = VaultManager::new()?;
        Ok(Self::with_parts(
            vault,
            vault_manager,
            AutoLockConfig::default(),
            Box::new(SystemClock::new()),
            Box::new(crate::clipboard::Clipboard::default()),
        ))
    }

    /// Builds an `App` from already constructed parts. Opens nothing and reads no global state.
    ///
    /// The App starts on the unlock screen, in setup mode when the vault is not yet initialized.
    pub(crate) fn with_parts(
        vault: Vault,
        vault_manager: VaultManager,
        auto_lock_config: AutoLockConfig,
        clock: Box<dyn Clock>,
        clipboard: Box<dyn crate::clipboard::ClipboardBackend>,
    ) -> Self {
        let vault_selector = VaultSelector::new();
        // Setup mode (create master password) when the vault has no master key yet.
        let master_mode_is_setup = !vault.is_initialized();

        Self {
            clipboard: crate::clipboard::SessionClipboard::new(clipboard),
            vault,
            vault_manager,
            vault_selector,

            screen: Screen::Unlock,
            master_input: String::new(),
            master_confirm_input: String::new(),
            master_mode_is_setup,
            unlock_focus: UnlockField::Master,
            error: None,
            items: vec![],
            selected: 0,
            view_mode: ViewMode::All,
            filtered_items: vec![],
            search_query: String::new(),
            search_mode: false,
            add_name: String::new(),
            add_kind_idx: 0,
            add_value: String::new(),
            add_value_scroll: 0,
            status_message: None,
            status_type: StatusType::Info,
            scroll_offset: 0,
            add_value_textarea: new_value_editor(),
            countdown_info: None,
            clock,
            auto_lock_config,
            last_activity: None,

            ck_current: String::new(),
            ck_new: String::new(),
            ck_confirm: String::new(),
            ck_focus: ChangeKeyField::Current,
            add_focus: AddItemField::Name,
            view_item: None,
            view_show_value: false,
            edit_item: None,
            edit_value: String::new(),

            // Initialize password generation fields
            gen_focus: PasswordGenField::Length,
            gen_length_str: "16".to_string(),
            gen_config: PasswordConfig::default(),
            generated_password: None,

            // Initialize import/export fields
            ie_focus: ImportExportField::Path,
            ie_mode: ImportExportMode::Export,
            ie_path: String::new(),
            ie_format_idx: 0,
            ie_formats: vec!["json", "csv", "backup"],
        }
    }

    fn validate_master_strength(s: &str) -> Result<()> {
        if s.len() < 8 {
            return Err(eyre!("Master key must be at least 8 characters long"));
        }
        if !s.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(eyre!("Master key must contain a lowercase letter"));
        }
        if !s.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(eyre!("Master key must contain an uppercase letter"));
        }
        if !s.chars().any(|c| c.is_ascii_digit()) {
            return Err(eyre!("Master key must contain a digit"));
        }
        Ok(())
    }

    /// Submits the unlock or setup form. Every outcome is handled here; nothing is returned to the event loop.
    ///
    /// In setup mode (the vault is not initialized yet), the two inputs must match and pass
    /// `validate_master_strength`, and then the vault is initialized. A failure sets `error` to
    /// "Passwords do not match", the strength message, or "Setup failed: {e}" and keeps the setup form.
    /// After a successful `initialize`, `master_mode_is_setup` becomes `false` for good and the same
    /// password continues into the unlock steps.
    ///
    /// The unlock steps unlock the vault and load its items. A wrong password sets `error` to
    /// "Invalid master password" and leaves the vault locked. If loading the items fails, the vault is
    /// locked again, the item caches are wiped, no timer runs, `status_message` is cleared, and `error` is
    /// "Unlock failed: could not load items: {e}". On success the items are cached, `error` and
    /// `status_message` are cleared, the main screen is shown, and the inactivity timer starts with a full
    /// interval when auto-lock is enabled.
    ///
    /// Whatever the outcome, `master_input` and `master_confirm_input` are zeroized and left empty, so the
    /// master password is never retained. `unlock_focus` is never changed.
    pub fn unlock(&mut self) {
        self.unlock_with(Vault::list_items);
    }

    /// `unlock` with the item loader as a parameter, so tests can supply one that fails.
    ///
    /// Production always passes `Vault::list_items`.
    pub(crate) fn unlock_with(&mut self, load_items: impl FnOnce(&Vault) -> Result<Vec<Item>>) {
        // Moving the buffers out (no copy) empties both fields now and zeroizes the bytes when these drop,
        // on every exit path of the attempt.
        let master = Zeroizing::new(std::mem::take(&mut self.master_input));
        let confirm = Zeroizing::new(std::mem::take(&mut self.master_confirm_input));
        self.attempt_unlock(&master, &confirm, load_items);
    }

    /// One unlock or setup attempt with borrowed inputs. See `unlock` for the outcomes.
    fn attempt_unlock(&mut self, master: &str, confirm: &str, load_items: impl FnOnce(&Vault) -> Result<Vec<Item>>) {
        if self.master_mode_is_setup {
            if master != confirm {
                self.error = Some("Passwords do not match".to_string());
                return;
            }
            if let Err(e) = Self::validate_master_strength(master) {
                self.error = Some(e.to_string());
                return;
            }
            if let Err(e) = self.vault.initialize(master) {
                self.error = Some(format!("Setup failed: {e}"));
                return;
            }
            // The vault is initialized now, so the setup form never comes back.
            self.master_mode_is_setup = false;
        }

        if self.vault.unlock(master).is_err() {
            self.error = Some("Invalid master password".to_string());
            return;
        }

        match load_items(&self.vault) {
            Ok(items) => {
                wipe_items(&mut self.items);
                wipe_items(&mut self.filtered_items);
                self.items = items;
                self.update_filtered_items();
                if self.selected >= self.filtered_items.len() && !self.filtered_items.is_empty() {
                    self.selected = self.filtered_items.len().saturating_sub(1);
                }
                self.error = None;
                self.status_message = None;
                self.screen = Screen::Main;
                // The inactivity timer starts here and nowhere else, after loading has finished.
                self.last_activity = if self.auto_lock_config.enabled {
                    Some(self.clock.now())
                } else {
                    None
                };
            }
            Err(e) => {
                self.vault.lock();
                wipe_items(&mut self.items);
                wipe_items(&mut self.filtered_items);
                self.last_activity = None;
                self.countdown_info = None;
                self.error = Some(format!("Unlock failed: could not load items: {e}"));
                self.status_message = None;
            }
        }
    }

    /// Refreshes the list of items and updates the filtered items.
    ///
    /// This method performs the following actions:
    /// 1. Updates the `items` field by retrieving the latest list of items from the `vault`.
    /// 2. Applies filtering logic to update the `filtered_items` list.
    /// 3. Ensures that the current selection (`selected`) is within the bounds of the updated `filtered_items` list.
    ///    If the current selection is out of bounds but the `filtered_items` list is not empty,
    ///    it adjusts `selected` to the last valid index.
    ///
    /// # Errors
    /// Returns an error if fetching the list of items from the `vault` fails.
    ///
    /// # Returns
    /// - `Ok(())` if the operation is successful.
    /// - `Err` with the specific error encountered when listing items from the `vault`.
    pub fn refresh_items(&mut self) -> Result<()> {
        self.items = self.vault.list_items()?;
        self.update_filtered_items();
        if self.selected >= self.filtered_items.len() && !self.filtered_items.is_empty() {
            self.selected = self.filtered_items.len().saturating_sub(1);
        }
        Ok(())
    }

    pub fn update_filtered_items(&mut self) {
        let mut filtered = self.items.clone();

        // Apply view mode filter
        if self.view_mode != ViewMode::All {
            filtered.retain(|item| match self.view_mode {
                ViewMode::Passwords => matches!(item.kind, ItemKind::Password),
                ViewMode::Environment => matches!(item.kind, ItemKind::EnvVar),
                ViewMode::Notes => matches!(item.kind, ItemKind::Note),
                ViewMode::All => true,
            });
        }

        // Apply search filter
        if !self.search_query.is_empty() {
            let query_lower = self.search_query.to_lowercase();
            filtered.retain(|item| {
                item.name.to_lowercase().contains(&query_lower) || item.value.to_lowercase().contains(&query_lower)
            });
        }

        // Sort by kind first, then by name
        filtered.sort_by(|a, b| {
            use std::cmp::Ordering;
            match a.kind.as_str().cmp(b.kind.as_str()) {
                Ordering::Equal => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                other => other,
            }
        });

        self.filtered_items = filtered;

        // Adjust selection if needed
        if self.selected >= self.filtered_items.len() && !self.filtered_items.is_empty() {
            self.selected = self.filtered_items.len() - 1;
        }
    }

    pub fn get_selected_item(&self) -> Option<&Item> {
        self.filtered_items.get(self.selected)
    }

    pub fn get_item_counts(&self) -> ItemCounts {
        let passwords = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Password))
            .count();
        let env_vars = self.items.iter().filter(|i| matches!(i.kind, ItemKind::EnvVar)).count();
        let notes = self.items.iter().filter(|i| matches!(i.kind, ItemKind::Note)).count();
        let api_keys = self.items.iter().filter(|i| matches!(i.kind, ItemKind::ApiKey)).count();
        let ssh_keys = self.items.iter().filter(|i| matches!(i.kind, ItemKind::SshKey)).count();
        let certificates = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Certificate))
            .count();
        let databases = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Database))
            .count();

        // New categories
        let credit_cards = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::CreditCard))
            .count();
        let secure_notes = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::SecureNote))
            .count();
        let identities = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Identity))
            .count();
        let servers = self.items.iter().filter(|i| matches!(i.kind, ItemKind::Server)).count();
        let wifi_passwords = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::WifiPassword))
            .count();
        let licenses = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::License))
            .count();
        let bank_accounts = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::BankAccount))
            .count();
        let documents = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Document))
            .count();
        let recovery_codes = self
            .items
            .iter()
            .filter(|i| matches!(i.kind, ItemKind::Recovery))
            .count();
        let oauth_tokens = self.items.iter().filter(|i| matches!(i.kind, ItemKind::OAuth)).count();

        ItemCounts {
            total: self.items.len(),
            passwords,
            env_vars,
            notes,
            api_keys,
            ssh_keys,
            certificates,
            databases,
            credit_cards,
            secure_notes,
            identities,
            servers,
            wifi_passwords,
            licenses,
            bank_accounts,
            documents,
            recovery_codes,
            oauth_tokens,
        }
    }

    /// Adds a new item to the vault with the specified details and updates the UI.
    ///
    /// # Description
    /// This function creates a new item based on the user input, validates it,
    /// and stores it in the vault. If the operation is successful, the UI is updated
    /// to reflect the addition and the input fields are reset. If an error occurs,
    /// appropriate error messages and statuses are set.
    ///
    /// # Fields Used
    /// - `add_kind_idx`: Determines the type of item being added (e.g., `Password`, `EnvVar`, `Note`, etc.).
    /// - `add_name`: The name of the new item, trimmed of whitespace.
    /// - `add_value_textarea`: The content or value of the new item, usually multi-line.
    /// - `vault`: The storage structure which handles item creation.
    /// - `add_value`: Secondary field for item value, cleared after addition.
    /// - `add_value_scroll`: Resets the scroll position of the textarea after addition.
    /// - `screen`: Sets the screen to the main view upon successful addition.
    /// - `error`: Displays error messages for failed operations.
    /// - `status`: Updates the user-visible status of the addition operation.
    ///
    /// # Process
    /// 1. Determines the item type (`kind`) based on `add_kind_idx`:
    ///    - `0` -> Password
    ///    - `1` -> Environment Variable
    ///    - `3` -> API Key
    ///    - `4` -> SSH Key
    ///    - `5` -> Certificate
    ///    - `6` -> Database
    ///    - Default -> Note
    /// 2. Fetches the item's value from the textarea (`add_value_textarea`), joining multiple lines with `\n`.
    /// 3. Creates a `NewItem` structure with the gathered data.
    /// 4. Attempts to add the item using `vault.create_item`.
    /// 5. Handles responses:
    ///    - **Success**: Resets input fields, updates item list, switches to the main screen, and displays a success message.
    ///    - **Failure**: If the name already exists, prompts the user to choose a different name. For other errors, displays a generic error message.
    ///
    /// # Returns
    /// Returns an `Ok(())` on successful completion of the process or propagates an error if any step fails.
    ///
    /// # Errors
    /// - Returns an error if refreshing the items (`refresh_items`) fails.
    /// - Updates the `error` and `status` fields with detailed context if item creation fails.
    ///
    /// # Notes
    /// - Resets both single-line (`add_value`) and multi-line (`add_value_textarea`) value fields upon successful addition.
    /// - Automatically trims leading and trailing whitespace from the item name.
    pub fn add_item(&mut self) -> Result<()> {
        let kind = ItemKind::all()[self.add_kind_idx.min(ItemKind::all().len() - 1)];

        // Get the value from the textarea instead of add_value
        let value = self.add_value_textarea.lines().join("\n");

        let new_item = NewItem {
            name: self.add_name.trim().to_string(),
            kind,
            value, // Use the textarea content
        };

        match self.vault.create_item(&new_item) {
            Ok(()) => {
                self.add_name.clear();
                self.add_value.clear();
                // Reset the textarea as well
                self.add_value_textarea = TextArea::default();
                self.add_value_scroll = 0;
                self.refresh_items()?;
                self.screen = Screen::Main;
                self.error = Some("Item added.".into());
                self.set_status("Item added successfully.".to_string(), StatusType::Success);
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("already exists") {
                    self.error = Some(format!("Item '{}' already exists.", new_item.name));
                    self.set_status(
                        format!(
                            "Item '{}' already exists. Please choose a different name.",
                            new_item.name
                        ),
                        StatusType::Warning,
                    );
                } else {
                    self.error = Some(format!("Failed to add item: {msg}"));
                    self.set_status(format!("Failed to add item: {msg}"), StatusType::Error);
                }
            }
        }
        Ok(())
    }

    /// Deletes the currently selected item from the vault.
    ///
    /// This function retrieves the currently selected item, deletes it from the vault
    /// using its unique identifier, and then refreshes the list of items to reflect the changes.
    /// If no item is selected, the function does nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Retrieving the selected item fails.
    /// - Deleting the item from the vault fails.
    /// - Refreshing the item list fails.
    pub fn delete_selected(&mut self) -> Result<()> {
        if let Some(item) = self.get_selected_item() {
            let item_id = item.id;
            self.vault.delete_item(item_id)?;
            self.refresh_items()?;
        }
        Ok(())
    }

    /// Changes the master key for the application if provided inputs meet the necessary conditions.
    ///
    /// This function performs several validations to ensure the master key change process is secure:
    /// 1. It checks if all required input fields (`ck_current`, `ck_new`, and `ck_confirm`) are filled.
    /// 2. It validates that the new master key (`ck_new`) matches the confirmation key (`ck_confirm`).
    /// 3. It verifies the strength of the new master key using the `validate_master_strength` method.
    ///
    /// If any of these conditions fail, an appropriate error message is stored in the `error` field,
    /// and the process halts without changing the master key.
    ///
    /// Once all validations are passed, the function updates the master key by calling the
    /// `change_master_key` method of the `vault`. After a successful update, it clears all input fields,
    /// resets the error message, and navigates back to the main screen.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the master key has been successfully changed or
    ///   the process ended due to a validation failure without panicking.
    /// * `Err(Error)` - If an error occurs while attempting to change the key in the `vault`.
    ///
    /// # Errors
    ///
    /// - If any of the following conditions occur, an error is stored in the `error` field,
    ///   and the function returns `Ok`:
    ///   - Any of the required fields (`ck_current`, `ck_new`, or `ck_confirm`) are empty.
    ///   - The new master key and confirmation key do not match.
    ///   - The new master key fails the strength validation.
    /// - If the `vault.change_master_key` method returns an error, it will propagate as a `Result::Err`.
    pub fn change_master(&mut self) -> Result<()> {
        if self.ck_current.is_empty() || self.ck_new.is_empty() || self.ck_confirm.is_empty() {
            self.error = Some("Please fill out all fields.".into());
            return Ok(());
        }
        if self.ck_new != self.ck_confirm {
            self.error = Some("New master keys do not match.".into());
            return Ok(());
        }
        if let Err(e) = Self::validate_master_strength(&self.ck_new) {
            self.error = Some(e.to_string());
            return Ok(());
        }
        self.vault.change_master_key(&self.ck_current, &self.ck_new)?;
        self.ck_current.clear();
        self.ck_new.clear();
        self.ck_confirm.clear();
        self.screen = Screen::Main;
        self.error = None;
        Ok(())
    }

    /// Copies the currently selected item to the clipboard.
    ///
    /// This function retrieves the currently selected item using the `get_selected_item` method.
    /// If an item is selected, it initializes the system clipboard, attempts to copy the selected
    /// item's value to the clipboard, and updates the status message to indicate success.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the item is successfully copied to the clipboard or no item is selected.
    /// * `Err(anyhow::Error)` - If there's an error while accessing the clipboard or copying the
    ///   item to the clipboard.
    ///
    /// # Errors
    ///
    /// - Returns an error if accessing the clipboard fails.
    /// - Returns an error if copying the selected item's value to the clipboard fails.
    ///
    /// # Behavior
    ///
    /// - If no item is selected (`get_selected_item` returns `None`), the function does nothing and
    ///   returns `Ok(())`.
    ///
    /// - If an item is selected (`get_selected_item` returns `Some`), it:
    ///   - Lazily initializes and retains the clipboard instance for the TUI lifetime.
    ///   - Copies the `value` of the selected item to the clipboard and remembers its digest, so `lock`
    ///     can clear it if it is still there.
    ///   - Sets a status message indicating that the item has been successfully copied to the clipboard.
    ///
    /// # Dependencies
    ///
    /// This function relies on the `arboard` crate for clipboard interactions and the `anyhow` crate
    /// for error handling. It also assumes the existence of the following methods:
    /// - `get_selected_item`: Retrieves the currently selected item, returning an option.
    /// - `set_status`: Updates the application's status message and type.
    ///
    pub fn copy_selected(&mut self) -> Result<()> {
        if let Some(item) = self.filtered_items.get(self.selected) {
            self.clipboard.copy(&item.value)?;
            self.set_status(format!("Copied '{}' to clipboard", item.name), StatusType::Success);
        }
        Ok(())
    }

    /// Copies the item displayed in the detail view, even while its value is hidden.
    ///
    /// # Errors
    /// Returns an error if the desktop clipboard cannot be accessed or written.
    pub fn copy_viewed(&mut self) -> Result<()> {
        if let Some(item) = &self.view_item {
            self.clipboard.copy(&item.value)?;
            self.set_status(format!("Copied '{}' to clipboard", item.name), StatusType::Success);
        }
        Ok(())
    }

    pub fn view_selected(&mut self) {
        if let Some(item) = self.get_selected_item() {
            self.view_item = Some(item.clone());
            self.view_show_value = false;
            self.screen = Screen::ViewItem;
        }
    }

    pub const fn toggle_value_visibility(&mut self) {
        self.view_show_value = !self.view_show_value;
    }

    pub fn edit_selected(&mut self) {
        let selected_item = self.get_selected_item().cloned();
        if let Some(item) = selected_item {
            self.edit_item = Some(item.clone());
            self.edit_value.clone_from(&item.value);
            self.screen = Screen::EditItem;
        }
    }

    /// Attempts to save edits made to an item in the vault and updates the user interface accordingly.
    ///
    /// # Behavior
    /// - If the `edit_value` is empty (after trimming), it sets an error message ("Value cannot be empty") and exits early.
    /// - Otherwise, it updates the item in the vault identified by `edit_item.id` with the new `edit_value`.
    /// - After updating the item, it clears the `edit_item` and `edit_value`, refreshes the list of items, and switches
    ///   the application's screen back to the main screen while clearing any previous errors.
    ///
    /// # Errors
    /// - If updating the vault fails, an error is propagated from the `vault.update_item` method.
    /// - If refreshing items fails, an error is propagated from the `refresh_items` method.
    ///
    /// # Returns
    /// - `Ok(())` if the edit is successfully saved or if the `edit_value` is empty.
    /// - `Err` if an error occurs during vault updates or refreshing items.
    ///
    /// # Fields/State
    /// - `self.edit_item`: The item currently being edited. If `None`, the method does nothing.
    /// - `self.edit_value`: The new value to be saved to the item. If empty (once trimmed), the method sets an error message and exits early.
    /// - `self.error`: An optional error message for display purposes. This is set if the `edit_value` is empty or cleared on successful operation.
    /// - `self.vault`: The storage mechanism used to update the item.
    /// - `self.screen`: Controls the application screen flow. Set to `Screen::Main` after a successful edit.
    ///
    pub fn save_edit(&mut self) -> Result<()> {
        if let Some(item) = &self.edit_item {
            if self.edit_value.trim().is_empty() {
                self.error = Some("Value cannot be empty".into());
                return Ok(());
            }

            self.vault.update_item(item.id, &self.edit_value)?;
            self.edit_item = None;
            self.edit_value.clear();
            self.refresh_items()?;
            self.screen = Screen::Main;
            self.error = None;
        }
        Ok(())
    }

    // Password generation methods
    pub fn open_password_generator(&mut self) {
        self.gen_focus = PasswordGenField::Length;
        self.gen_length_str = self.gen_config.length.to_string();
        self.generated_password = None;
        self.error = None;
        self.screen = Screen::GeneratePassword;
    }

    pub fn generate_password(&mut self) {
        if let Ok(length) = self.gen_length_str.parse::<usize>() {
            self.gen_config.length = length.clamp(4, 128);
        } else {
            self.error = Some("Invalid length".into());
            return;
        }

        match self.gen_config.generate() {
            Ok(password) => {
                self.generated_password = Some(password);
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("Generation failed: {e}"));
            }
        }
    }

    /// Copies the generated password to the system clipboard.
    ///
    /// This function attempts to access the generated password stored in the `self.generated_password`
    /// field and copies it to the system clipboard using the `arboard` crate. If the operation succeeds,
    /// a success message is set in the `self.error` field. In the event of an error while accessing the
    /// clipboard or copying the text, the function returns a corresponding error.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the password is successfully copied to the clipboard or no password was generated.
    /// * `Err(anyhow::Error)` - If accessing the clipboard or copying the password fails.
    ///
    /// # Errors
    ///
    /// This function may return an error in the following scenarios:
    /// * Failure to access or initialize the system clipboard.
    /// * Failure to copy the generated password to the clipboard.
    ///
    /// # Side Effects
    ///
    /// * If a password is successfully copied to the clipboard, the `self.error` field is set with a success message.
    ///
    /// # Dependencies
    ///
    /// This function makes use of the `arboard` crate for clipboard access and text manipulation.
    pub fn copy_generated_password(&mut self) -> Result<()> {
        if let Some(password) = &self.generated_password {
            self.clipboard.copy(password)?;
            self.error = Some("Password copied to clipboard".into());
        }
        Ok(())
    }

    pub fn use_generated_password(&mut self) {
        if let Some(password) = &self.generated_password {
            self.add_value = password.clone();
            self.screen = Screen::AddItem;
            self.add_focus = AddItemField::Name;
        }
    }

    // Import/Export methods
    pub fn open_import_export(&mut self, mode: ImportExportMode) {
        self.ie_mode = mode;
        self.ie_focus = ImportExportField::Path;
        self.ie_path.clear();
        self.ie_format_idx = 0;
        self.error = None;
        self.screen = Screen::ImportExport;
    }

    /// Executes the import or export operation based on the current application state.
    ///
    /// This method performs the following operations:
    /// 1. Validates the provided file path and ensures it is not empty.
    /// 2. Normalizes the file path to handle different path separators and expand the home directory.
    /// 3. Determines the format of import/export (CSV, JSON, or backup).
    /// 4. Executes the import or export operation based on the selected mode (`ImportExportMode`).
    ///
    /// ### Export Mode
    /// - Creates necessary parent directories if they do not exist.
    /// - Exports the current items to the specified file path in the selected format.
    /// - Sets an appropriate success message indicating the number of items exported and the file path.
    ///
    /// ### Import Mode
    /// - Ensures the specified file exists before proceeding.
    /// - Imports items from the file in the specified format.
    /// - Avoids importing duplicate items by checking against existing item names.
    /// - Records the number of imported and skipped items due to duplication or errors.
    /// - Updates the item list after a successful import and presents an appropriate summary message.
    ///
    /// ### Errors
    /// - If the file path is empty, a user-friendly error message is set and the operation is aborted.
    /// - If a directory creation fails during export, an error is returned.
    /// - If certain items cannot be imported due to conflicts or other errors, they are counted as skipped.
    ///
    /// ### Remarks
    /// - Upon completion (successful or not), the application state is updated to the main screen.
    ///
    /// ### Returns
    /// - `Ok(())` if the operation completes successfully (even if some items were skipped).
    /// - `Err` if a file path normalization or file operation fails during the execution.
    ///
    /// ### Preconditions
    /// - `self.ie_path` must be set to a valid file path.
    /// - The `self.ie_formats` array must include supported formats ("csv", "backup", "json").
    /// - The `self.items` list is expected to contain the current application items for export/import validation.
    ///
    /// ### Postconditions
    /// - Updates `self.error` with a descriptive message about the operation result.
    /// - Changes the application state screen to `Screen::Main`.
    pub fn execute_import_export(&mut self) -> Result<()> {
        if self.ie_path.trim().is_empty() {
            self.error = Some("Please enter a file path".into());
            return Ok(());
        }

        // Normalize the path to handle different separators and expand the home directory
        let normalized_path = app::App::normalize_path(&self.ie_path)?;
        let path = PathBuf::from(normalized_path);

        let format = match self.ie_formats[self.ie_format_idx] {
            "csv" => ExportFormat::Csv,
            "backup" => ExportFormat::ChamberBackup,
            _ => ExportFormat::Json,
        };

        match self.ie_mode {
            ImportExportMode::Export => {
                // Create parent directories if they don't exist
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| eyre!("Failed to create directory {}: {}", parent.display(), e))?;
                    }
                }

                export_items(&self.items, &format, &path)?;
                self.error = Some(format!("Exported {} items to {}", self.items.len(), path.display()));
            }
            ImportExportMode::Import => {
                if !path.exists() {
                    self.error = Some(format!("File does not exist: {}", path.display()));
                    return Ok(());
                }

                let new_items = import_items(&path, &format)?;
                if new_items.is_empty() {
                    self.error = Some("No items found in file".into());
                    return Ok(());
                }

                let existing_names: std::collections::HashSet<String> =
                    self.items.iter().map(|item| item.name.clone()).collect();

                let mut imported_count = 0;
                let mut skipped_count = 0;

                for item in new_items {
                    if existing_names.contains(&item.name) {
                        skipped_count += 1;
                        continue;
                    }

                    match self.vault.create_item(&item) {
                        Ok(()) => imported_count += 1,
                        Err(_) => skipped_count += 1,
                    }
                }

                self.refresh_items()?;
                self.error = Some(format!("Imported {imported_count} items, skipped {skipped_count}"));
            }
        }

        self.screen = Screen::Main;
        Ok(())
    }

    // Helper method to normalize file paths
    fn normalize_path(input_path: &str) -> Result<String> {
        let path_str = input_path.trim();

        // Handle home directory expansion
        let expanded_path = if path_str.strip_prefix('~').is_some() {
            if let Some(home_dir) = dirs::home_dir() {
                let rest = &path_str[1..];
                let rest = if rest.starts_with('/') || rest.starts_with('\\') {
                    &rest[1..]
                } else {
                    rest
                };
                home_dir.join(rest).to_string_lossy().to_string()
            } else {
                return Err(eyre!("Unable to determine home directory"));
            }
        } else {
            path_str.to_string()
        };

        // Convert forward slashes to native path separators on Windows
        #[cfg(windows)]
        let normalized = expanded_path.replace('/', "\\");

        #[cfg(not(windows))]
        let normalized = expanded_path;

        Ok(normalized)
    }

    pub fn set_status(&mut self, message: String, status_type: StatusType) {
        self.status_message = Some(message);
        self.status_type = status_type;
    }

    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    pub fn is_in_input_mode(&self) -> bool {
        match self.screen {
            Screen::AddItem
            | Screen::EditItem
            | Screen::ChangeMaster
            | Screen::GeneratePassword
            | Screen::ImportExport
            | Screen::Unlock => true,
            Screen::Main if !self.search_query.is_empty() => true, // Search mode
            _ => false,
        }
    }

    /// Pastes content from the clipboard to the add item value field.
    ///
    /// This function retrieves text content from the system clipboard and appends it to
    /// the current `add_value` field. If the clipboard contains text, it will be added
    /// to the existing value. If accessing the clipboard fails, an appropriate status
    /// message is displayed.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the paste operation completes successfully or if there's no text in clipboard.
    /// * `Err(anyhow::Error)` - If accessing the clipboard fails.
    ///
    /// # Errors
    ///
    /// - Returns an error if accessing the clipboard fails.
    /// - Sets a warning status if the clipboard is empty or contains no text.
    ///
    /// # Behavior
    ///
    /// - Retrieves text from the system clipboard using `arboard::Clipboard`.
    /// - Appends the clipboard content to the current `add_value` field.
    /// - Sets a success status message indicating the paste operation completed.
    /// - If clipboard is empty or contains no text, shows a warning message.
    pub fn paste_to_add_value(&mut self) -> Result<()> {
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            if let Ok(text) = clipboard.get_text() {
                // Clear existing content and insert new text
                self.add_value_textarea.select_all();
                self.add_value_textarea.cut();
                self.add_value_textarea.insert_str(text);
                self.set_status("Pasted from clipboard".to_string(), StatusType::Success);
                Ok(())
            } else {
                self.set_status("No text in clipboard".to_string(), StatusType::Warning);
                Ok(())
            }
        } else {
            self.set_status("Failed to access clipboard".to_string(), StatusType::Error);
            Ok(())
        }
    }

    pub fn open_vault_selector(&mut self) {
        self.vault_selector.load_vaults(&self.vault_manager);
        self.vault_selector.show();
        self.screen = Screen::VaultSelector;
    }

    /// Handles various actions related to vault management.
    ///
    /// This function processes the provided `VaultAction` and executes the corresponding logic
    /// to manage vaults, such as creating, updating, deleting, importing, and more.
    ///
    /// # Arguments
    ///
    /// * `action` - A `VaultAction` enum that specifies the action to be performed. Each variant
    ///   of `VaultAction` corresponds to a specific vault-related operation.
    ///
    /// # Returns
    ///
    /// * `Result<()>` - Returns `Ok(())` if the action was processed successfully; otherwise,
    ///   an error is returned if any operation fails.
    ///
    /// # `VaultAction` Variants
    ///
    /// - `VaultAction::Switch(vault_id)`
    ///   Switches to the specified vault by its ID.
    ///
    /// - `VaultAction::Create { name, description, category }`
    ///   Creates a new vault with the provided name, description, and category.
    ///
    /// - `VaultAction::Update { vault_id, name, description, category, favorite }`
    ///   Updates an existing vault with the given parameters, including optional fields like the
    ///   vault name, description, category, and favorite status.
    ///
    /// - `VaultAction::Delete { vault_id, delete_file }`
    ///   Deletes a vault specified by its ID. If `delete_file` is true, related files are also deleted.
    ///
    /// - `VaultAction::Import { path }`
    ///   Imports a vault from a specified file path.
    ///
    /// - `VaultAction::Refresh`
    ///   Reloads the list of available vaults and updates the UI to reflect any changes. Sets
    ///   a success status message indicating the vaults have been refreshed.
    ///
    /// - `VaultAction::Close`
    ///   Hides the vault selector and switches back to the main screen.
    ///
    /// - `VaultAction::ShowHelp`
    ///   Displays help information. (This action may be handled or ignored based on needs.)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Switching to a vault fails.
    /// - The requested vault action encounters an issue (e.g., file access issues during imports or
    ///   failures in vault creation/deletion).
    pub fn handle_vault_action(&mut self, action: VaultAction) -> Result<()> {
        match action {
            VaultAction::Switch(vault_id) => {
                self.switch_to_vault(&vault_id)?;
            }
            VaultAction::Create {
                name,
                description,
                category,
            } => {
                self.create_vault(&name, description, &category);
            }
            VaultAction::Update {
                vault_id,
                name,
                description,
                category,
                favorite,
            } => {
                self.update_vault(vault_id, name, description, category, favorite);
            }
            VaultAction::Delete { vault_id, delete_file } => {
                self.delete_vault(&vault_id, delete_file);
            }
            VaultAction::Import { path } => {
                self.import_vault(&path);
            }
            VaultAction::Refresh => {
                self.vault_selector.load_vaults(&self.vault_manager);
                self.set_status("Vaults refreshed".to_string(), StatusType::Success);
            }
            VaultAction::Close => {
                self.vault_selector.hide();
                self.screen = Screen::Main;
            }
            VaultAction::ShowHelp => {
                // You can handle help display here or ignore it
            }
        }
        Ok(())
    }

    fn switch_to_vault(&mut self, vault_id: &str) -> Result<String> {
        // First, switch the active vault in the registry
        self.vault_manager.switch_active_vault(vault_id)?;

        // Try to open the vault with the current master password
        match self.vault_manager.open_vault(vault_id, &self.master_input) {
            Ok(()) => {
                // Successfully opened vault in the manager
                // Now we need to create our own unlocked instance
                let vault_info = self
                    .vault_manager
                    .registry
                    .get_vault(vault_id)
                    .ok_or_else(|| eyre!("Vault with id {} not found", vault_id))?;
                let mut new_vault = chamber_vault::Vault::open_or_create(Some(&vault_info.path))?;
                new_vault.unlock(&self.master_input)?;

                // Replace our vault with the newly unlocked one
                self.vault = new_vault;
                self.refresh_items()?;
                self.set_status(format!("Switched to vault: {vault_id}"), StatusType::Success);
            }
            Err(_) => {
                // This vault has a different master password
                self.vault_selector.error_message = Some(format!(
                    "Vault '{vault_id}' was created with a different master password. \
                Please delete this vault and create a new one, or use the master password change feature to migrate it."
                ));
            }
        }

        Ok(String::from(vault_id))
    }

    fn create_vault(&mut self, name: &str, description: Option<String>, category: &str) {
        // Parse category
        let vault_category = match category.to_lowercase().as_str() {
            "personal" => chamber_vault::VaultCategory::Personal,
            "work" => chamber_vault::VaultCategory::Work,
            "team" => chamber_vault::VaultCategory::Team,
            "project" => chamber_vault::VaultCategory::Project,
            "testing" => chamber_vault::VaultCategory::Testing,
            "archive" => chamber_vault::VaultCategory::Archive,
            custom => chamber_vault::VaultCategory::Custom(custom.to_string()),
        };

        // In a real implementation, you'd prompt for a password
        let password = &self.master_input;

        // Validate that we have a password
        if password.is_empty() {
            self.vault_selector.error_message = Some("Master password is required to create vault".to_string());
        }

        match self
            .vault_manager
            .create_vault(name.to_string(), None, vault_category, description, password)
        {
            Ok(_vault_id) => {
                self.vault_selector.load_vaults(&self.vault_manager);
                self.vault_selector.mode = VaultSelectorMode::Select;
                self.set_status(format!("Created vault: {name}"), StatusType::Success);
            }
            Err(e) => {
                self.vault_selector.error_message = Some(format!("Failed to create vault: {e}"));
            }
        }
    }

    fn update_vault(
        &mut self,
        vault_id: String,
        name: Option<String>,
        description: Option<String>,
        category: Option<String>,
        favorite: Option<bool>,
    ) {
        let vault_category = category.map(|cat_str| match cat_str.to_lowercase().as_str() {
            "personal" => chamber_vault::VaultCategory::Personal,
            "work" => chamber_vault::VaultCategory::Work,
            "team" => chamber_vault::VaultCategory::Team,
            "project" => chamber_vault::VaultCategory::Project,
            "testing" => chamber_vault::VaultCategory::Testing,
            "archive" => chamber_vault::VaultCategory::Archive,
            custom => chamber_vault::VaultCategory::Custom(custom.to_string()),
        });

        match self
            .vault_manager
            .update_vault_info(&vault_id, name.clone(), description, vault_category, favorite)
        {
            Ok(()) => {
                self.vault_selector.load_vaults(&self.vault_manager);
                self.vault_selector.mode = VaultSelectorMode::Select;
                self.set_status(
                    format!("Updated vault: {}", name.unwrap_or(vault_id)),
                    StatusType::Success,
                );
            }
            Err(e) => {
                self.vault_selector.error_message = Some(format!("Failed to update vault: {e}"));
            }
        }
    }

    fn delete_vault(&mut self, vault_id: &str, delete_file: bool) {
        let is_active_vault = self.vault_manager.registry.active_vault_id.as_ref() == Some(&vault_id.to_string());
        let vault_count = self.vault_manager.registry.vaults.len();

        // Prevent deletion of an active vault unless it's the only one
        if is_active_vault && vault_count > 1 {
            self.set_status(
                "Cannot delete active vault. Switch to another vault first.".to_string(),
                StatusType::Error,
            );
            return;
        }

        match self.vault_manager.delete_vault(vault_id, delete_file) {
            Ok(()) => {
                self.vault_selector.load_vaults(&self.vault_manager);
                self.vault_selector.mode = VaultSelectorMode::Select;
                self.set_status(format!("Deleted vault: {vault_id}"), StatusType::Success);
            }
            Err(e) => {
                self.set_status(format!("Failed to delete vault: {e}"), StatusType::Error);
            }
        }
    }

    fn import_vault(&mut self, path: &str) {
        let path_buf = std::path::PathBuf::from(&path);
        let name = path_buf
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Imported Vault")
            .to_string();

        match self
            .vault_manager
            .import_vault(&path_buf, name.clone(), chamber_vault::VaultCategory::Personal, true)
        {
            Ok(_vault_id) => {
                self.vault_selector.load_vaults(&self.vault_manager);
                self.vault_selector.mode = VaultSelectorMode::Select;
                self.set_status(format!("Imported vault: {name}"), StatusType::Success);
            }
            Err(e) => {
                self.vault_selector.error_message = Some(format!("Failed to import vault: {e}"));
            }
        }
    }

    /// Takes a reading from the App's clock.
    pub(crate) fn now(&self) -> ClockReading {
        self.clock.now()
    }

    /// The configured inactivity timeout.
    const fn auto_lock_timeout(&self) -> Duration {
        Duration::from_secs(self.auto_lock_config.inactivity_timeout_minutes.saturating_mul(60))
    }

    /// Inactivity since `since`: the larger of the monotonic and wall-clock elapsed times.
    ///
    /// The wall clock makes suspended time count. Taking the larger of the two means moving the wall clock
    /// backward cannot extend a session, while moving it forward can lock early.
    fn elapsed_inactivity(since: ClockReading, now: ClockReading) -> Duration {
        let monotonic = now.monotonic.saturating_sub(since.monotonic);
        let wall = now.wall.duration_since(since.wall).unwrap_or(Duration::ZERO);
        monotonic.max(wall)
    }

    /// Time left before auto-lock, floored at zero. `None` when no timer is running.
    pub(crate) fn time_until_auto_lock(&self, now: ClockReading) -> Option<Duration> {
        self.last_activity.map(|since| {
            self.auto_lock_timeout()
                .saturating_sub(Self::elapsed_inactivity(since, now))
        })
    }

    /// Restarts the inactivity timer. Does nothing while locked or when auto-lock is disabled.
    pub(crate) const fn record_activity(&mut self, now: ClockReading) {
        if self.vault.is_unlocked() && self.auto_lock_config.enabled {
            self.last_activity = Some(now);
        }
    }

    /// Locks the App when it is unlocked and the inactivity timer has expired. Returns whether it locked.
    pub(crate) fn lock_if_expired(&mut self, now: ClockReading) -> bool {
        let expired = self
            .last_activity
            .is_some_and(|since| Self::elapsed_inactivity(since, now) >= self.auto_lock_timeout());
        if self.vault.is_unlocked() && expired {
            self.lock();
            true
        } else {
            false
        }
    }

    /// One timer step of the event loop: locks on expiry, then recomputes the countdown.
    pub(crate) fn tick(&mut self, now: ClockReading) {
        self.lock_if_expired(now);
        self.countdown_info = if self.vault.is_unlocked() {
            self.time_until_auto_lock(now).map(|remaining| {
                let secs = i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX);
                CountdownInfo {
                    enabled: true,
                    minutes_left: secs / 60,
                    seconds_left: secs,
                }
            })
        } else {
            None
        };
    }

    /// Locks the TUI. This is the single function that does so.
    ///
    /// Does nothing when already locked, so a password being typed on the unlock form is never erased.
    /// Otherwise, in this order: drops the vault key, closes every vault the manager holds open, stops the
    /// inactivity timer, discards the ended session's state (see below), clears the clipboard if it still
    /// holds the value this session last copied, sets the status to "Locked due to inactivity", and returns
    /// to the unlock screen. The registry and the vault's database path are untouched, so the same vault can
    /// be unlocked again.
    ///
    /// Clipboard step: when nothing was copied this session, the clipboard is not read, cleared, or even
    /// opened. Otherwise it is read and cleared only if its text has the SHA-256 digest of the last copied
    /// value, or if it cannot be read at all; different text or no text is left alone. Either way the stored
    /// digest is zeroized and removed and the retained clipboard handle is released. A failed clear changes
    /// the status to "Locked due to inactivity. Clipboard could not be cleared." as a warning, and never
    /// stops the rest of the lock. Copies that clipboard managers or other applications already took are
    /// out of reach.
    ///
    /// The lock always completes, whatever screen or dialog is open. Unsaved edits and drafts are discarded
    /// without saving or prompting. After a lock, no live application state can show, restore, or receive
    /// as input anything from the ended session:
    ///
    /// - Decrypted caches: `items` and `filtered_items` have each value zeroized and are emptied;
    ///   `view_item` and `edit_item` have their value zeroized and become `None`.
    /// - Password fields: `master_input`, `master_confirm_input`, `ck_current`, `ck_new`, and `ck_confirm`
    ///   are zeroized and left empty.
    /// - Other text buffers: `add_value`, `edit_value`, `search_query`, `add_name`, `ie_path`, and the vault
    ///   selector's `input_buffer` are zeroized and left empty; `generated_password` is zeroized and becomes
    ///   `None`.
    /// - The add-item editor is replaced by a fresh one configured as at startup. The old editor's lines
    ///   are zeroized, and consuming it drops its undo/redo history and yank buffer, so nothing can be
    ///   restored from them. Those private allocations are released, not proven to be overwritten.
    /// - Input modes and reveal state: `search_mode` and `view_show_value` become `false`, and the vault
    ///   selector is hidden and back in select mode with no input field, error, or confirmation message.
    ///   Its vault list and list selection are kept.
    /// - Positions (`selected`, `scroll_offset`, `add_value_scroll`, `add_kind_idx`) become `0`, every focus
    ///   field returns to its startup value, and `error` becomes `None`.
    ///
    /// Preferences survive a lock: `view_mode`, `gen_config`, `gen_length_str`, `ie_mode`, `ie_format_idx`,
    /// and `master_mode_is_setup` keep their values.
    ///
    /// Buffers the App owns directly are wiped before release. This does not claim to erase copies the
    /// allocator, the operating system, the terminal, or a dependency may have made earlier.
    pub fn lock(&mut self) {
        if !self.vault.is_unlocked() {
            return;
        }
        self.vault.lock();
        self.vault_manager.close_all_vaults();
        self.last_activity = None;
        self.countdown_info = None;
        self.discard_session_state();
        if self.clipboard.clear_at_lock() {
            self.set_status(
                "Locked due to inactivity. Clipboard could not be cleared.".to_string(),
                StatusType::Warning,
            );
        } else {
            self.set_status("Locked due to inactivity".to_string(), StatusType::Info);
        }
        self.screen = Screen::Unlock;
    }

    /// Whether the session clipboard holds the digest of a copied value.
    #[cfg(test)]
    pub(crate) const fn clipboard_digest_stored(&self) -> bool {
        self.clipboard.has_digest()
    }

    /// Wipes and resets everything `lock` discards. See `lock` for the list.
    fn discard_session_state(&mut self) {
        // Decrypted caches.
        wipe_items(&mut self.items);
        wipe_items(&mut self.filtered_items);
        wipe_item(&mut self.view_item);
        wipe_item(&mut self.edit_item);

        // Password fields.
        wipe_string(&mut self.master_input);
        wipe_string(&mut self.master_confirm_input);
        wipe_string(&mut self.ck_current);
        wipe_string(&mut self.ck_new);
        wipe_string(&mut self.ck_confirm);

        // Other text buffers and drafts.
        wipe_string(&mut self.add_value);
        wipe_string(&mut self.edit_value);
        wipe_string(&mut self.search_query);
        wipe_string(&mut self.add_name);
        wipe_string(&mut self.ie_path);
        wipe_optional_string(&mut self.generated_password);
        wipe_editor(&mut self.add_value_textarea);

        // Input modes, reveal state, and dialogs.
        self.search_mode = false;
        self.view_show_value = false;
        self.vault_selector.reset_on_lock();

        // Positions and focus.
        self.selected = 0;
        self.scroll_offset = 0;
        self.add_value_scroll = 0;
        self.add_kind_idx = 0;
        self.unlock_focus = UnlockField::Master;
        self.ck_focus = ChangeKeyField::Current;
        self.add_focus = AddItemField::Name;
        self.gen_focus = PasswordGenField::Length;
        self.ie_focus = ImportExportField::Path;

        self.error = None;
    }

    // Synchronous method for the drawing function
    pub const fn get_countdown_info(&self) -> Option<&CountdownInfo> {
        self.countdown_info.as_ref()
    }
}

/// Zeroizes each item's secret `value`, then empties the vector.
///
/// Item names are stored unencrypted, so they are not zeroized.
pub(crate) fn wipe_items(items: &mut Vec<Item>) {
    for item in items.iter_mut() {
        item.value.zeroize();
    }
    items.clear();
}

/// Builds the add-item value editor exactly as configured at startup.
///
/// Used by `App::with_parts` and by the lock cleanup, so a fresh editor always matches the initial one.
pub(crate) fn new_value_editor() -> TextArea<'static> {
    let mut textarea = TextArea::default();
    // Enable line numbers
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    textarea.set_cursor_line_style(Style::default());
    textarea.set_placeholder_text("Enter your value here...");
    textarea
}

/// Zeroizes the string's buffer and leaves it empty.
pub(crate) fn wipe_string(s: &mut String) {
    s.zeroize();
}

/// Zeroizes the held string, if any, then sets the option to `None`.
pub(crate) fn wipe_optional_string(s: &mut Option<String>) {
    if let Some(inner) = s.as_mut() {
        inner.zeroize();
    }
    *s = None;
}

/// Zeroizes the held item's secret `value`, if any, then sets the option to `None`.
///
/// Item names are stored unencrypted, so they are not zeroized.
pub(crate) fn wipe_item(item: &mut Option<Item>) {
    if let Some(inner) = item.as_mut() {
        inner.value.zeroize();
    }
    *item = None;
}

/// Replaces the editor with a fresh one from `new_value_editor` and zeroizes every line of the old one.
///
/// Consuming the old editor with `into_lines` drops its undo/redo history and yank buffer, so the new
/// editor cannot restore them. Those private allocations are released, not proven to be overwritten.
pub(crate) fn wipe_editor(editor: &mut TextArea<'static>) {
    let old = std::mem::replace(editor, new_value_editor());
    for mut line in old.into_lines() {
        line.zeroize();
    }
}
