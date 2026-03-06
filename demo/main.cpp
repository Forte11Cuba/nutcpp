#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <string>
#include <vector>

using namespace ftxui;

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

int main() {
    auto screen = ScreenInteractive::Fullscreen();

    int selected = 0;

    std::vector<std::string> labels;
    for (auto& item : menu_items)
        labels.push_back(item.label);

    auto menu = Menu(&labels, &selected);

    std::string status_text = "Not connected";

    auto layout = Renderer(menu, [&]() -> Element {
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

        // Right panel
        Element content;
        if (item.coming_soon) {
            content = text("Coming soon...") | dim | hcenter | vcenter;
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
        Element status_bar = text(status_text) | color(Color::Cyan);

        // Main layout
        Element main_layout = vbox({
            hbox({left_panel, right_panel}) | flex,
            status_bar,
        });

        return main_layout;
    });

    auto main_component = CatchEvent(layout, [&](Event event) {
        if (event == Event::Escape) {
            screen.Exit();
            return true;
        }
        return false;
    });

    screen.Loop(main_component);
    return 0;
}
