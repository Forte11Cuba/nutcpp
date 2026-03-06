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

#include "nutcpp/api/cashu_http_client.h"
#include "nutcpp/api/cashu_error.h"
#include "nutcpp/api_models/info_response.h"
#include "nutcpp/api_models/keysets_response.h"

using namespace ftxui;

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
static std::atomic<bool> g_shutdown{false};
static std::unique_ptr<std::thread> g_fetch_thread;

static void fetch_mint_info(ScreenInteractive* screen) {
    std::string url;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_mint_info.loading = true;
        g_mint_info.error.clear();
        g_mint_info.has_info = false;
        url = g_mint_info.url_input;
    }
    if (g_shutdown.load()) return;
    screen->PostEvent(Event::Custom);

    try {
        auto client = std::make_unique<nutcpp::api::CashuHttpClient>(url);
        auto info = client->get_info();
        auto keysets = client->get_keysets();

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
        if (!g_mint_info.loading) {
            if (g_fetch_thread && g_fetch_thread->joinable())
                g_fetch_thread->join();
            g_fetch_thread = std::make_unique<std::thread>(fetch_mint_info, &screen);
        }
    });

    auto mint_info_controls = Container::Horizontal({
        mint_url_input,
        connect_button,
    });

    // All interactive components: menu + mint info controls
    auto all_components = Container::Vertical({
        menu,
        mint_info_controls,
    });

    auto layout = Renderer(all_components, [&]() -> Element {
        auto& item = menu_items[selected];

        // Left panel
        Element left_title = text("nutcpp demo") | bold | color(Color::Cyan) | hcenter;
        Element menu_el = menu->Render() | vscroll_indicator | yframe | flex;
        Element esc_hint = text("ESC = quit") | hcenter | dim;

        Element left_panel = vbox({
            left_title,
            separator(),
            menu_el,
            separator(),
            esc_hint,
        });
        left_panel = left_panel | border | size(WIDTH, EQUAL, 22);

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
        } else {
            content = text("Select an option to begin") | dim | hcenter | vcenter;
        }

        Element right_panel = vbox({
            text(item.title) | bold,
            separator(),
            content | flex,
        });
        right_panel = right_panel | border | flex;

        // Status bar
        std::string status;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            status = g_status;
        }
        Element status_bar = text(status) | color(Color::Cyan);

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

    return 0;
}
