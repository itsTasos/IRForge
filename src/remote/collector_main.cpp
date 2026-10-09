#include "irforge/remote/TlsTransport.hpp"
#include <QCoreApplication>
#include <algorithm>
#include <iostream>
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    try {
        std::vector<std::string> args;
        for (const auto &value : app.arguments()) {
            auto bytes = value.toUtf8();
            args.emplace_back(bytes.constData(), static_cast<std::size_t>(bytes.size()));
        }
        if (args.size() == 1 || std::find(args.begin(), args.end(), "--help") != args.end()) {
            std::cout << "IRForge optional metadata collector (mTLS, no remote commands)\n"
                         "  irforge_collector serve --config FILE [--allow-network]\n"
                         "  irforge_collector status --db FILE --fingerprint SHA256\n"
                         "  irforge_collector enroll --db FILE --fingerprint SHA256 --agent-id ID --host-id "
                         "ID --role agent|viewer|admin [--allowed-hosts IDS] --confirm\n"
                         "  irforge_collector revoke --db FILE --fingerprint SHA256 --confirm\n";
            return 0;
        }
        return irforge::collectorApplication(args);
    } catch (const std::exception &e) {
        std::cerr << "IRForge collector error: " << e.what() << '\n';
        return 2;
    }
}
