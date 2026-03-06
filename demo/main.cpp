#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <numeric>
#include <cstdio>
#include <cinttypes>


#include "nutcpp/api/cashu_http_client.h"
#include "nutcpp/api/cashu_error.h"
#include "nutcpp/api_models/info_response.h"
#include "nutcpp/api_models/keysets_response.h"
#include "nutcpp/api_models/keys_response.h"
#include "nutcpp/api_models/mint_models.h"
#include "nutcpp/wallet/blinding_helper.h"
#include "nutcpp/encoding/token_helper.h"

using namespace ftxui;

// ============================================================
// Cashu glasses logo (pixel art)
// ============================================================

static Element render_logo() {
    // X = glasses pixel (black), B = reflection pixel (white), space = purple bg
    // Padded with 1 char purple on each side + 1 full purple row top/bottom
    static const std::vector<std::string> art = {
        "                                ",  // top purple row
        " XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX ",
        "  XXBXBXXXXXXXX  XXXBXBXXXXXXXX ",
        "   XXBXBXXXXXXX  XXXXBXBXXXXXX  ",
        "    XXBXBXXXX     XXXXBXBXXXX   ",
        "     XXXXXXX       XXXXXXXXX    ",
        "                                ",  // bottom purple row
    };

    auto purple = Color(147, 51, 234);

    Elements lines;
    for (auto& row : art) {
        Elements chars;
        for (char c : row) {
            if (c == 'X')
                chars.push_back(text(" ") | bgcolor(Color::Black));
            else if (c == 'B')
                chars.push_back(text(" ") | bgcolor(Color::White));
            else
                chars.push_back(text(" ") | bgcolor(purple));
        }
        lines.push_back(hbox(std::move(chars)));
    }
    return vbox(std::move(lines));
}

// ============================================================
// Menu definition
// ============================================================

struct MenuItem {
    std::string label;
    std::string title;
    bool coming_soon;
};

static const std::vector<MenuItem> menu_items = {
    {"Mint Info",        "Mint Information (NUT-06)",           false},
    {"Deposit LN",       "Deposit Lightning (NUT-04)",          false},
    {"Withdraw LN",      "Withdraw Lightning (NUT-05)",         false},
    {"Receive eCash",    "Receive eCash",                       false},
    {"Send eCash",       "Send eCash",                          false},
    {"Token Inspector",  "Token Inspector (NUT-00)",            false},
    {"Wallet",           "Wallet",                              false},
    {"Check States",     "Check States (NUT-07)",               false},
    {"Swap",             "Swap (NUT-03)",                       false},
    {"Secrets",          "Secrets (NUT-10)",                    false},
    {"NUT-13",           "Deterministic Secrets (NUT-13)",      true},
    {"P2PK / HTLC",      "Spending Conditions (NUT-11/14)",     true},
    {"Payment Request",  "Payment Requests (NUT-18/26)",        true},
};

// ============================================================
// Shared state
// ============================================================

static std::mutex g_mutex;
static std::unique_ptr<nutcpp::api::CashuHttpClient> g_client;
static std::string g_mint_url;
static std::string g_status = "Not connected";
static std::atomic<bool> g_shutdown{false};

// Clipboard helper — tries xclip, xsel, wl-copy via popen (no shell interpolation)
static bool copy_to_clipboard(const std::string& text) {
    const char* cmds[] = {
        "xclip -selection clipboard",
        "xsel --clipboard --input",
        "wl-copy",
    };
    for (auto* cmd : cmds) {
        FILE* pipe = popen(cmd, "w");
        if (!pipe) continue;
        fwrite(text.data(), 1, text.size(), pipe);
        if (pclose(pipe) == 0) return true;
    }
    return false;
}

// Active keyset (keys + id) — fetched on connect
static nutcpp::api::KeysResponseItem* g_active_keyset = nullptr;
static std::vector<nutcpp::api::KeysResponseItem> g_keys_items;

// ============================================================
// Wallet state (global)
// ============================================================

static std::vector<nutcpp::Proof> g_wallet_proofs;

static uint64_t wallet_balance_locked() {
    uint64_t total = 0;
    for (auto& p : g_wallet_proofs)
        total += p.amount;
    return total;
}

// ============================================================
// Deposit LN screen state (declared early — used in fetch_mint_info)
// ============================================================

struct DepositLNState {
    std::string amount_input = "100";
    bool loading = false;
    std::string error;
    std::string status_msg;

    // Quote
    bool has_quote = false;
    uint64_t quote_amount = 0;
    std::string quote_id;
    std::string invoice;
    std::string quote_state;

    // Minted proofs
    bool has_proofs = false;
    struct ProofRow {
        std::string amount;
        std::string keyset;
        std::string secret_short;
    };
    std::vector<ProofRow> minted_proofs;
    uint64_t minted_total = 0;
};

static DepositLNState g_deposit;

// ============================================================
// Mint Info screen state
// ============================================================

struct MintInfoState {
    std::string url_input = "https://testnut.cashu.space";
    bool loading = false;
    std::string error;

    // Results
    bool has_info = false;
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::pair<std::string, std::string>> contacts;
    std::vector<std::string> supported_nuts;

    // Keysets
    struct KeysetRow {
        std::string id;
        std::string unit;
        std::string active;
        std::string fee;
    };
    std::vector<KeysetRow> keysets;
};

static MintInfoState g_mint_info;
static std::unique_ptr<std::thread> g_fetch_thread;

static void fetch_mint_info(ScreenInteractive* screen, std::string url) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_mint_info.loading = true;
        g_mint_info.error.clear();
        g_mint_info.has_info = false;
    }
    if (g_shutdown.load()) return;
    screen->PostEvent(Event::Custom);

    try {
        auto client = std::make_unique<nutcpp::api::CashuHttpClient>(url);
        auto info = client->get_info();
        auto keysets = client->get_keysets();
        auto keys_resp = client->get_keys();

        std::lock_guard<std::mutex> lock(g_mutex);

        g_mint_info.name = info.name.value_or("Unknown");
        g_mint_info.version = info.version.value_or("Unknown");
        g_mint_info.description = info.description.value_or("No description");

        g_mint_info.contacts.clear();
        if (info.contact.has_value()) {
            for (auto& c : info.contact.value())
                g_mint_info.contacts.emplace_back(c.method, c.info);
        }

        g_mint_info.supported_nuts.clear();
        if (info.nuts.has_value()) {
            for (auto& [num, _] : info.nuts.value())
                g_mint_info.supported_nuts.push_back(num);
            std::sort(g_mint_info.supported_nuts.begin(),
                      g_mint_info.supported_nuts.end(),
                      [](const std::string& a, const std::string& b) {
                          try { return std::stoi(a) < std::stoi(b); }
                          catch (...) { return a < b; }
                      });
        }

        g_mint_info.keysets.clear();
        for (auto& ks : keysets.keysets) {
            MintInfoState::KeysetRow row;
            row.id = ks.id.to_string();
            row.unit = ks.unit;
            row.active = ks.active ? "yes" : "no";
            row.fee = ks.input_fee_ppk.has_value()
                ? std::to_string(ks.input_fee_ppk.value()) + " ppk"
                : "-";
            g_mint_info.keysets.push_back(std::move(row));
        }

        // Store keys for blinding/unblinding
        g_keys_items = std::move(keys_resp.keysets);
        g_active_keyset = nullptr;
        for (auto& ki : g_keys_items) {
            if (ki.active.value_or(false) && ki.unit == "sat") {
                g_active_keyset = &ki;
                break;
            }
        }

        // Clear deposit/wallet state from previous mint
        // Reset selectively — do NOT touch amount_input (bound to FTXUI Input on UI thread)
        g_deposit.loading = false;
        g_deposit.error.clear();
        g_deposit.status_msg.clear();
        g_deposit.has_quote = false;
        g_deposit.quote_amount = 0;
        g_deposit.quote_id.clear();
        g_deposit.invoice.clear();
        g_deposit.quote_state.clear();
        g_deposit.has_proofs = false;
        g_deposit.minted_proofs.clear();
        g_deposit.minted_total = 0;
        g_wallet_proofs.clear();

        g_mint_url = url;
        g_status = "Connected to " + g_mint_url;
        g_client = std::move(client);
        g_mint_info.has_info = true;
        g_mint_info.loading = false;

    } catch (const nutcpp::api::CashuProtocolException& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_mint_info.error = std::string("Mint error: ") + e.what();
        g_mint_info.loading = false;
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_mint_info.error = e.what();
        g_mint_info.loading = false;
    }

    if (!g_shutdown.load())
        screen->PostEvent(Event::Custom);
}

// ============================================================
// Mint Info screen renderer
// ============================================================

static Element render_mint_info() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_mint_info.loading) {
        return text("Connecting...") | dim | hcenter | vcenter;
    }

    if (!g_mint_info.error.empty()) {
        return vbox({
            text("Error: " + g_mint_info.error) | color(Color::Red),
        });
    }

    if (!g_mint_info.has_info) {
        return text("Enter a mint URL and press Connect") | dim | hcenter | vcenter;
    }

    // Info section
    Elements info_lines;
    info_lines.push_back(hbox({text("Name:    ") | bold, text(g_mint_info.name)}));
    info_lines.push_back(hbox({text("Version: ") | bold, text(g_mint_info.version)}));
    info_lines.push_back(hbox({text("Desc:    ") | bold, text(g_mint_info.description)}));

    if (!g_mint_info.contacts.empty()) {
        info_lines.push_back(text(""));
        info_lines.push_back(text("Contact") | bold | underlined);
        for (auto& [method, info] : g_mint_info.contacts)
            info_lines.push_back(hbox({text("  " + method + ": "), text(info)}));
    }

    // Supported NUTs
    if (!g_mint_info.supported_nuts.empty()) {
        std::string nuts_str;
        for (size_t i = 0; i < g_mint_info.supported_nuts.size(); i++) {
            if (i > 0) nuts_str += ", ";
            nuts_str += g_mint_info.supported_nuts[i];
        }
        info_lines.push_back(text(""));
        info_lines.push_back(hbox({text("NUTs:    ") | bold, text(nuts_str)}));
    }

    // Keysets table
    if (!g_mint_info.keysets.empty()) {
        info_lines.push_back(text(""));
        info_lines.push_back(text("Keysets") | bold | underlined);

        // Header
        info_lines.push_back(hbox({
            text("  ID") | bold | size(WIDTH, EQUAL, 20),
            text("Unit") | bold | size(WIDTH, EQUAL, 8),
            text("Active") | bold | size(WIDTH, EQUAL, 8),
            text("Fee") | bold,
        }));

        for (auto& ks : g_mint_info.keysets) {
            std::string short_id = ks.id.size() > 16
                ? ks.id.substr(0, 16) + "..."
                : ks.id;
            info_lines.push_back(hbox({
                text("  " + short_id) | size(WIDTH, EQUAL, 20),
                text(ks.unit) | size(WIDTH, EQUAL, 8),
                text(ks.active) | size(WIDTH, EQUAL, 8)
                    | (ks.active == "yes" ? color(Color::Green) : color(Color::Red)),
                text(ks.fee),
            }));
        }
    }

    return vbox(std::move(info_lines)) | vscroll_indicator | yframe;
}

static std::unique_ptr<std::thread> g_deposit_thread;

static void do_create_quote(ScreenInteractive* screen, uint64_t amount) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.loading = true;
        g_deposit.error.clear();
        g_deposit.status_msg = "Creating quote...";
        g_deposit.has_quote = false;
        g_deposit.has_proofs = false;
        if (!g_client) {
            g_deposit.error = "Not connected to a mint. Go to Mint Info first.";
            g_deposit.loading = false;
            return;
        }
    }
    if (g_shutdown.load()) return;
    screen->PostEvent(Event::Custom);

    try {
        nutcpp::api::PostMintQuoteBolt11Request req(amount, "sat");
        auto resp = g_client->create_mint_quote<
            nutcpp::api::PostMintQuoteBolt11Request,
            nutcpp::api::PostMintQuoteBolt11Response>("bolt11", req);

        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.quote_amount = amount;
        g_deposit.quote_id = resp.quote;
        g_deposit.invoice = resp.request;
        g_deposit.quote_state = resp.state;
        g_deposit.has_quote = true;
        g_deposit.loading = false;
        g_deposit.status_msg = "Quote created. Pay the invoice, then check status.";

    } catch (const nutcpp::api::CashuProtocolException& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.error = std::string("Mint error: ") + e.what();
        g_deposit.loading = false;
    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.error = e.what();
        g_deposit.loading = false;
    }

    if (!g_shutdown.load())
        screen->PostEvent(Event::Custom);
}

static void do_check_and_mint(ScreenInteractive* screen) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.loading = true;
        g_deposit.error.clear();
        g_deposit.status_msg = "Checking quote status...";
    }
    if (g_shutdown.load()) return;
    screen->PostEvent(Event::Custom);

    try {
        auto resp = g_client->check_mint_quote<
            nutcpp::api::PostMintQuoteBolt11Response>("bolt11", g_deposit.quote_id);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_deposit.quote_state = resp.state;
        }
        screen->PostEvent(Event::Custom);

        if (resp.state == "PAID") {
            // Auto-mint: proceed to claim tokens immediately
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_deposit.status_msg = "Invoice paid! Minting tokens...";
            }
            screen->PostEvent(Event::Custom);

            uint64_t amount;
            std::string quote_id;
            nutcpp::Keyset keyset;
            nutcpp::KeysetId kid("0000000000000000"); // reassigned below
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                amount = g_deposit.quote_amount;
                quote_id = g_deposit.quote_id;
                if (!g_active_keyset) {
                    g_deposit.error = "No active sat keyset found";
                    g_deposit.loading = false;
                    screen->PostEvent(Event::Custom);
                    return;
                }
                kid = g_active_keyset->id;
                keyset = g_active_keyset->keys;
            }

            auto amounts = nutcpp::wallet::split_amount(amount);
            auto outputs = nutcpp::wallet::create_blinded_outputs(amounts, kid);

            nutcpp::api::PostMintRequest mint_req(quote_id, outputs.blinded_messages);
            auto mint_resp = g_client->mint<
                nutcpp::api::PostMintRequest,
                nutcpp::api::PostMintResponse>("bolt11", mint_req);

            auto proofs = nutcpp::wallet::unblind_signatures(
                mint_resp.signatures, outputs.blinding_data, keyset);

            std::lock_guard<std::mutex> lock(g_mutex);
            g_deposit.minted_proofs.clear();
            g_deposit.minted_total = 0;
            for (auto& p : proofs) {
                DepositLNState::ProofRow row;
                row.amount = std::to_string(p.amount);
                row.keyset = p.id.to_string().substr(0, 16) + "...";
                row.secret_short = p.secret.size() > 16
                    ? p.secret.substr(0, 16) + "..."
                    : p.secret;
                g_deposit.minted_proofs.push_back(std::move(row));
                g_deposit.minted_total += p.amount;
                g_wallet_proofs.push_back(std::move(p));
            }
            g_deposit.has_proofs = true;
            g_deposit.loading = false;
            g_deposit.quote_state = "ISSUED";
            g_deposit.status_msg = "Minted " + std::to_string(g_deposit.minted_total) + " sats!";

        } else {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_deposit.loading = false;
            if (resp.state == "ISSUED")
                g_deposit.status_msg = "Tokens already issued for this quote.";
            else
                g_deposit.status_msg = "State: " + resp.state + ". Pay the invoice and check again.";
        }

    } catch (const std::exception& e) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_deposit.error = e.what();
        g_deposit.loading = false;
    }

    if (!g_shutdown.load())
        screen->PostEvent(Event::Custom);
}


// ============================================================
// Deposit LN screen renderer
// ============================================================

static Element render_deposit_ln() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_client) {
        return text("Connect to a mint first (Mint Info screen)") | dim | hcenter | vcenter;
    }

    Elements lines;

    // Error
    if (!g_deposit.error.empty()) {
        lines.push_back(text("Error: " + g_deposit.error) | color(Color::Red));
        lines.push_back(text(""));
    }

    // Loading
    if (g_deposit.loading) {
        lines.push_back(text(g_deposit.status_msg) | dim);
        return vbox(std::move(lines));
    }

    // Status message
    if (!g_deposit.status_msg.empty() && g_deposit.error.empty()) {
        auto msg_color = Color::White;
        if (g_deposit.quote_state == "PAID")
            msg_color = Color::Green;
        else if (g_deposit.quote_state == "ISSUED")
            msg_color = Color::Cyan;
        lines.push_back(text(g_deposit.status_msg) | color(msg_color));
        lines.push_back(text(""));
    }

    // Quote info
    if (g_deposit.has_quote) {
        lines.push_back(text("Quote") | bold | underlined);
        lines.push_back(hbox({text("  ID:      ") | bold, text(g_deposit.quote_id)}));

        // Invoice rendered as interactive Input in the main layout

        auto state_color = Color::Yellow;
        if (g_deposit.quote_state == "PAID") state_color = Color::Green;
        else if (g_deposit.quote_state == "ISSUED") state_color = Color::Cyan;
        lines.push_back(hbox({
            text("  State:   ") | bold,
            text(g_deposit.quote_state) | color(state_color) | bold,
        }));
        lines.push_back(text(""));
    }

    // Minted proofs
    if (g_deposit.has_proofs) {
        lines.push_back(text("Minted Proofs") | bold | underlined);
        lines.push_back(hbox({
            text("  Amount") | bold | size(WIDTH, EQUAL, 10),
            text("Keyset") | bold | size(WIDTH, EQUAL, 22),
            text("Secret") | bold,
        }));
        for (auto& row : g_deposit.minted_proofs) {
            lines.push_back(hbox({
                text("  " + row.amount) | size(WIDTH, EQUAL, 10) | color(Color::Green),
                text(row.keyset) | size(WIDTH, EQUAL, 22),
                text(row.secret_short) | dim,
            }));
        }
        lines.push_back(text(""));
        lines.push_back(hbox({
            text("  Total minted: ") | bold,
            text(std::to_string(g_deposit.minted_total) + " sats") | color(Color::Green) | bold,
        }));
    }

    if (lines.empty()) {
        return text("Enter an amount and create a quote") | dim | hcenter | vcenter;
    }

    return vbox(std::move(lines)) | vscroll_indicator | yframe;
}

// ============================================================
// Token Inspector helpers
// ============================================================

// Cashu amounts are in the smallest unit of the currency:
// "sat" → satoshis, "msat" → millisatoshis, "usd"/"eur" → cents.
// Format for display: cents-based units get decimal point (100 → "1.00").
static std::string format_amount(uint64_t raw, const std::string& unit) {
    if (unit == "usd" || unit == "eur") {
        uint64_t whole = raw / 100;
        uint64_t frac = raw % 100;
        char buf[64];
        snprintf(buf, sizeof(buf), "%" PRIu64 ".%02" PRIu64, whole, frac);
        return std::string(buf) + " " + unit;
    }
    return std::to_string(raw) + " " + unit;
}

// ============================================================
// Token Inspector screen state
// ============================================================

struct TokenInspectorState {
    std::string token_input;
    std::string error;

    // Decoded result
    bool has_result = false;
    std::string version;   // "A" or "B"
    std::string unit;
    std::string memo;

    struct MintGroup {
        std::string mint;
        struct ProofRow {
            std::string amount;
            std::string keyset;
            std::string secret;
            std::string C;
        };
        std::vector<ProofRow> proofs;
        uint64_t total = 0;
    };
    std::vector<MintGroup> mint_groups;
    uint64_t grand_total = 0;
    size_t total_proofs = 0;

    // Re-encoded strings (empty = encode failed)
    std::string encoded_v3;
    std::string encoded_v4;
    std::string encode_v3_error;
    std::string encode_v4_error;

    // Copy feedback
    std::string status_msg;
};

static TokenInspectorState g_inspector;

static void do_decode_token() {
    g_inspector.error.clear();
    g_inspector.has_result = false;
    g_inspector.encoded_v3.clear();
    g_inspector.encoded_v4.clear();
    g_inspector.status_msg.clear();

    if (g_inspector.token_input.empty()) {
        g_inspector.error = "Paste a token string (cashuA... or cashuB...)";
        return;
    }

    try {
        std::string version;
        auto token = nutcpp::encoding::TokenHelper::decode(
            g_inspector.token_input, version);

        g_inspector.version = version;
        g_inspector.unit = token.unit.value_or("-");
        g_inspector.memo = token.memo.value_or("-");
        g_inspector.mint_groups.clear();
        g_inspector.grand_total = 0;
        g_inspector.total_proofs = 0;

        for (auto& t : token.tokens) {
            TokenInspectorState::MintGroup group;
            group.mint = t.mint;
            group.total = 0;
            for (auto& p : t.proofs) {
                TokenInspectorState::MintGroup::ProofRow row;
                row.amount = std::to_string(p.amount);
                row.keyset = p.id.to_string();
                if (row.keyset.size() > 16)
                    row.keyset = row.keyset.substr(0, 16) + "...";
                row.secret = p.secret.size() > 24
                    ? p.secret.substr(0, 24) + "..."
                    : p.secret;
                std::string c_hex = p.C.to_hex();
                row.C = c_hex.size() > 16
                    ? c_hex.substr(0, 16) + "..."
                    : c_hex;
                group.proofs.push_back(std::move(row));
                group.total += p.amount;
                g_inspector.grand_total += p.amount;
                g_inspector.total_proofs++;
            }
            g_inspector.mint_groups.push_back(std::move(group));
        }

        // Re-encode to both formats
        g_inspector.encode_v3_error.clear();
        g_inspector.encode_v4_error.clear();
        try { g_inspector.encoded_v3 = nutcpp::encoding::TokenHelper::encode(token, "A"); }
        catch (const std::exception& e) { g_inspector.encoded_v3.clear(); g_inspector.encode_v3_error = e.what(); }
        try { g_inspector.encoded_v4 = nutcpp::encoding::TokenHelper::encode(token, "B"); }
        catch (const std::exception& e) { g_inspector.encoded_v4.clear(); g_inspector.encode_v4_error = e.what(); }

        g_inspector.has_result = true;

    } catch (const std::exception& e) {
        g_inspector.error = e.what();
    }
}

static Element render_token_inspector() {
    if (!g_inspector.error.empty()) {
        return text("Error: " + g_inspector.error) | color(Color::Red);
    }

    if (!g_inspector.has_result) {
        return text("Paste a cashuA/cashuB token and press Decode") | dim | hcenter | vcenter;
    }

    Elements lines;

    // Copy feedback
    if (!g_inspector.status_msg.empty()) {
        lines.push_back(text(g_inspector.status_msg) | color(Color::Green));
        lines.push_back(text(""));
    }

    // Header info
    std::string ver_label = g_inspector.version == "A" ? "V3 (JSON)" : "V4 (CBOR)";
    lines.push_back(hbox({text("Format:  ") | bold, text(ver_label) | color(Color::Cyan)}));
    lines.push_back(hbox({text("Unit:    ") | bold, text(g_inspector.unit)}));
    lines.push_back(hbox({text("Memo:    ") | bold, text(g_inspector.memo)}));
    lines.push_back(hbox({
        text("Total:   ") | bold,
        text(format_amount(g_inspector.grand_total, g_inspector.unit)) | color(Color::Green) | bold,
        text("  (" + std::to_string(g_inspector.total_proofs) + " proofs)") | dim,
    }));

    // Proofs per mint
    for (auto& group : g_inspector.mint_groups) {
        lines.push_back(text(""));
        lines.push_back(hbox({
            text("Mint: ") | bold | underlined,
            text(group.mint) | underlined,
        }));

        // Table header
        lines.push_back(hbox({
            text("  Amount") | bold | size(WIDTH, EQUAL, 10),
            text("Keyset") | bold | size(WIDTH, EQUAL, 22),
            text("Secret") | bold | size(WIDTH, EQUAL, 28),
            text("C") | bold,
        }));

        for (auto& row : group.proofs) {
            lines.push_back(hbox({
                text("  " + row.amount) | size(WIDTH, EQUAL, 10) | color(Color::Green),
                text(row.keyset) | size(WIDTH, EQUAL, 22),
                text(row.secret) | size(WIDTH, EQUAL, 28) | dim,
                text(row.C) | dim,
            }));
        }

        lines.push_back(hbox({
            text("  Subtotal: ") | bold,
            text(format_amount(group.total, g_inspector.unit)) | color(Color::Yellow),
        }));
    }

    // Re-encoded tokens
    lines.push_back(text(""));
    lines.push_back(text("Re-encoded") | bold | underlined);

    if (!g_inspector.encoded_v3.empty())
        lines.push_back(hbox({text("  cashuA: ") | bold, text(g_inspector.encoded_v3) | dim}));
    else
        lines.push_back(hbox({text("  cashuA: ") | bold, text(g_inspector.encode_v3_error) | color(Color::Red)}));

    if (!g_inspector.encoded_v4.empty())
        lines.push_back(hbox({text("  cashuB: ") | bold, text(g_inspector.encoded_v4) | dim}));
    else
        lines.push_back(hbox({text("  cashuB: ") | bold, text(g_inspector.encode_v4_error) | color(Color::Red)}));

    return vbox(std::move(lines)) | vscroll_indicator | yframe;
}

// ============================================================
// Main
// ============================================================

int main() {
    auto screen = ScreenInteractive::Fullscreen();

    int selected = 0;

    std::vector<std::string> labels;
    for (auto& item : menu_items)
        labels.push_back(item.label);

    auto menu = Menu(&labels, &selected);

    // Mint Info input + button
    auto mint_url_input = Input(&g_mint_info.url_input, "https://mint.example.com");

    auto connect_button = Button("Connect", [&] {
        bool can_start = false;
        std::string url_snapshot;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            can_start = !g_mint_info.loading;
            url_snapshot = g_mint_info.url_input;
        }
        if (can_start) {
            if (g_fetch_thread && g_fetch_thread->joinable())
                g_fetch_thread->join();
            g_fetch_thread = std::make_unique<std::thread>(
                fetch_mint_info, &screen, std::move(url_snapshot));
        }
    });

    auto mint_info_controls = Container::Horizontal({
        mint_url_input,
        connect_button,
    });

    // Deposit LN input + buttons
    auto deposit_amount_input = Input(&g_deposit.amount_input, "100");

    // Read-only renderer for invoice — avoids data race with worker thread
    auto deposit_invoice_view = Renderer([&] {
        std::string invoice;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            invoice = g_deposit.invoice;
        }
        return text(invoice);
    });

    auto create_quote_button = Button("Create Quote", [&] {
        bool can_start = false;
        uint64_t amount = 0;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            can_start = !g_deposit.loading;
            if (can_start) {
                try {
                    amount = std::stoull(g_deposit.amount_input);
                } catch (...) {
                    g_deposit.error = "Invalid amount";
                    return;
                }
                if (amount == 0) {
                    g_deposit.error = "Amount must be > 0";
                    return;
                }
            }
        }
        if (can_start) {
            if (g_deposit_thread && g_deposit_thread->joinable())
                g_deposit_thread->join();
            g_deposit_thread = std::make_unique<std::thread>(
                do_create_quote, &screen, amount);
        }
    });

    auto copy_invoice_button = Button("Copy", [&] {
        std::string invoice;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            invoice = g_deposit.invoice;
        }
        if (!invoice.empty()) {
            bool ok = copy_to_clipboard(invoice);
            std::lock_guard<std::mutex> lock(g_mutex);
            g_deposit.status_msg = ok ? "Invoice copied to clipboard!"
                                      : "Copy failed — install xclip or wl-copy";
        }
    });

    auto check_status_button = Button("Check Status", [&] {
        bool can_check = false;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            can_check = !g_deposit.loading && g_deposit.has_quote;
        }
        if (can_check) {
            if (g_deposit_thread && g_deposit_thread->joinable())
                g_deposit_thread->join();
            g_deposit_thread = std::make_unique<std::thread>(do_check_and_mint, &screen);
        }
    });

    auto deposit_controls = Container::Vertical({
        Container::Horizontal({
            deposit_amount_input,
            create_quote_button,
            check_status_button,
        }),
        Container::Horizontal({
            deposit_invoice_view,
            copy_invoice_button,
        }),
    });

    // Token Inspector input + buttons
    auto inspector_token_input = Input(&g_inspector.token_input, "cashuA... or cashuB...");

    auto decode_button = Button("Decode", [&] {
        do_decode_token();
    });

    auto copy_v3_button = Button("Copy cashuA", [&] {
        if (g_inspector.encoded_v3.empty()) {
            g_inspector.status_msg = "V3 encode failed - nothing to copy";
            return;
        }
        bool ok = copy_to_clipboard(g_inspector.encoded_v3);
        g_inspector.status_msg = ok ? "cashuA copied to clipboard!"
                                    : "Copy failed - install xclip or wl-copy";
    });

    auto copy_v4_button = Button("Copy cashuB", [&] {
        if (g_inspector.encoded_v4.empty()) {
            g_inspector.status_msg = "V4 encode failed - nothing to copy";
            return;
        }
        bool ok = copy_to_clipboard(g_inspector.encoded_v4);
        g_inspector.status_msg = ok ? "cashuB copied to clipboard!"
                                    : "Copy failed - install xclip or wl-copy";
    });

    auto inspector_copy_controls = Container::Horizontal({
        copy_v3_button,
        copy_v4_button,
    }) | Maybe([&] { return g_inspector.has_result; });

    auto inspector_controls = Container::Vertical({
        Container::Horizontal({
            inspector_token_input,
            decode_button,
        }),
        inspector_copy_controls,
    });

    // Right panel: only the active screen's controls are visible and focusable.
    // Using Maybe instead of Container::Tab to avoid focus-stealing issues.
    auto right_content = Container::Stacked({
        mint_info_controls | Maybe([&] { return selected == 0; }),
        deposit_controls   | Maybe([&] { return selected == 1; }),
        inspector_controls | Maybe([&] { return selected == 5; }),
    });

    // Horizontal: menu (left) | active screen controls (right)
    auto all_components = Container::Horizontal({
        menu,
        right_content,
    });

    auto layout = Renderer(all_components, [&]() -> Element {
        auto& item = menu_items[selected];

        // Left panel
        Element left_title = text("nutcpp demo") | bold | color(Color::Cyan) | hcenter;
        Element menu_el = menu->Render() | vscroll_indicator | yframe | flex;
        Element esc_hint = text("ESC = quit") | hcenter | dim;

        Element left_panel = vbox({
            left_title,
            render_logo() | hcenter,
            separator(),
            menu_el,
            separator(),
            esc_hint,
        });
        left_panel = left_panel | border | size(WIDTH, EQUAL, 34);

        // Right panel content
        Element content;
        if (item.coming_soon) {
            content = text("Coming soon...") | dim | hcenter | vcenter;
        } else if (selected == 0) {
            // Mint Info screen
            Element url_row = hbox({
                text("URL: ") | bold,
                mint_url_input->Render() | flex,
                text(" "),
                connect_button->Render(),
            });
            content = vbox({
                url_row,
                separator(),
                render_mint_info() | flex,
            });
        } else if (selected == 1) {
            // Deposit LN screen
            bool has_quote;
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                has_quote = g_deposit.has_quote;
            }

            Elements controls;
            controls.push_back(text("Amount (sats): ") | bold);
            controls.push_back(deposit_amount_input->Render() | size(WIDTH, EQUAL, 12));
            controls.push_back(text(" "));
            controls.push_back(create_quote_button->Render());
            if (has_quote) {
                controls.push_back(text(" "));
                controls.push_back(check_status_button->Render());
            }

            Elements deposit_elements;
            deposit_elements.push_back(hbox(std::move(controls)));
            deposit_elements.push_back(separator());

            if (has_quote) {
                deposit_elements.push_back(
                    hbox({text("Invoice: ") | bold,
                          deposit_invoice_view->Render() | flex,
                          text(" "),
                          copy_invoice_button->Render()}) );
                deposit_elements.push_back(separator());
            }

            deposit_elements.push_back(render_deposit_ln() | flex);

            content = vbox(std::move(deposit_elements));
        } else if (selected == 5) {
            // Token Inspector screen
            Element token_row = hbox({
                text("Token: ") | bold,
                inspector_token_input->Render() | flex,
                text(" "),
                decode_button->Render(),
            });

            Elements inspector_elements;
            inspector_elements.push_back(token_row);
            inspector_elements.push_back(separator());

            if (g_inspector.has_result) {
                inspector_elements.push_back(hbox({
                    copy_v3_button->Render(),
                    text(" "),
                    copy_v4_button->Render(),
                }));
                inspector_elements.push_back(separator());
            }

            inspector_elements.push_back(render_token_inspector() | flex);
            content = vbox(std::move(inspector_elements));
        } else {
            content = text("Select an option to begin") | dim | hcenter | vcenter;
        }

        Element right_panel = vbox({
            text(item.title) | bold,
            separator(),
            content | flex,
        });
        right_panel = right_panel | border | flex;

        // Status bar with balance
        std::string status;
        uint64_t balance = 0;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            status = g_status;
            balance = wallet_balance_locked();
        }
        Element status_bar = hbox({
            text(status) | color(Color::Cyan),
            filler(),
            text("Balance: " + std::to_string(balance) + " sats") | bold | color(Color::Yellow),
        });

        // Main layout
        return vbox({
            hbox({left_panel, right_panel}) | flex,
            status_bar,
        });
    });

    auto main_component = CatchEvent(layout, [&](Event event) {
        if (event == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(main_component);

    g_shutdown.store(true);
    if (g_fetch_thread && g_fetch_thread->joinable())
        g_fetch_thread->join();
    if (g_deposit_thread && g_deposit_thread->joinable())
        g_deposit_thread->join();

    return 0;
}
