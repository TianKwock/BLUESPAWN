#include "hunt/hunts/HuntT9999.h"

#include <string>
#include <vector>
#include <memory>
#include <sstream>

#include "util/log/Log.h"
#include "util/registry/Registry.h"
#include "util/filesystem/FileSystem.h"
#include "util/metadata/FileMetadata.h"
#include "util/strings/StringUtils.h"

#include "user/bluespawn.h"

// subsection ID 
#define NP_LOGON_NOTIFIER 0

namespace Hunts {

    HuntT9999::HuntT9999() : Hunt(L"T9999 - NPLogonNotifiers") {
        dwCategoriesAffected = (DWORD)Category::Persistence | (DWORD)Category::CredentialAccess;
        dwSourcesInvolved = (DWORD)DataSource::Registry | (DWORD)DataSource::FileSystem;
        dwTacticsUsed = (DWORD)Tactic::Persistence;
    }

    void HuntT9999::Subtechnique006(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections) {
        // Initialize hunt macros
        SUBTECHNIQUE_INIT(006, NPLogonNotifiers);
        SUBSECTION_INIT(NP_LOGON_NOTIFIER, Normal);

        // Locating registry key containing provider order, since NPLogonNotifiers rely on "Network Providers"
        const std::wstring providerOrderKey = L"SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order";
        const std::wstring providerOrderValue = L"ProviderOrder";
        
        std::wstring providerOrder;

        // Log warning if ProviderOrder value can't be read from registry; end hunt
        if (!Registry::ReadStringValue(HKEY_LOCAL_MACHINE, providerOrderKey, providerOrderValue, providerOrder)) {
            LOG_WARN(L"Failed to read ProviderOrder registry value.");
            SUBSECTION_END();
            SUBTECHNIQUE_END();
            return;
        }

        // Split ProviderOrder into individual parameters
        auto providers = StringUtils::Split(providerOrder, L',');

        // Iterate through the providers
        for (auto& provider : providers) {
            // Trim whitespace and skip empty entries
            provider = StringUtils::Trim(provider);
            if (provider.empty()) continue;
            // Get associated DLL path for each provider 
            std::wstring dllPath;
            std::wstring providerRegKey = L"SYSTEM\\CurrentControlSet\\Services\\" + provider + L"\\NetworkProvider";

            // Warn if unable to find ProviderPath value 
            if (!Registry::ReadStringValue(HKEY_LOCAL_MACHINE, providerRegKey, L"ProviderPath", dllPath)) {
                LOG_WARN(L"Failed to read ProviderPath for: " << provider);
                continue;
            }

            // Verify existence of the DLL
            dllPath = FileSystem::ExpandEnvironmentStrings(dllPath);
            if (!FileSystem::FileExists(dllPath)) {
                LOG_WARN(L"DLL not found at path: " << dllPath);
                continue;
            }

            // Extract DLL metadata
            std::wstring version = FileMetadata::GetFileVersion(dllPath);
            std::wstring description = FileMetadata::GetFileDescription(dllPath);
            std::wstring signer = FileMetadata::GetSignerSubject(dllPath);

            bool suspicious = false;
            std::wstring reason;

            // Unsigned DLLs are suspicious
            if (signer.empty()) {
                suspicious = true;
                reason = L"Unsigned DLL";
            }
            // DLLs signed by someone other than Microsoft (will create false positives, but better safe than sorry)
            else if (signer.find(L"Microsoft") == std::wstring::npos) {
                suspicious = true;
                reason = L"Non-Microsoft signer: " + signer;
            }

            // Create detection if there is something suspicious
            if (suspicious) {
                CREATE_DETECTION(Certainty::Strong,
                                 RegistryDetectionData{ providerRegKey, L"ProviderPath", dllPath },
                                 FileDetectionData{ dllPath },
                                 ExtraDetectionData{
                                     L"Provider: " + provider,
                                     L"Version: " + version,
                                     L"Description: " + description,
                                     L"Signer: " + (signer.empty() ? L"Unsigned" : signer),
                                     reason
                                 });
            }
        }

        SUBSECTION_END();
        SUBTECHNIQUE_END();
    }

    // Run the hunt
    std::vector<std::shared_ptr<Detection>> HuntT9999::RunHunt(const Scope& scope) {
        HUNT_INIT();
        Subtechnique006(scope, detections);
        HUNT_END();
    }

}
