#pragma once
#include "../Hunt.h"

namespace Hunts {
    /**
     * HuntT9999 searches for malicious or suspicious Network Providers loaded during user logon. 
     * 
     * T9999: Reads from registry key HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order and analyzes each listed provider's DLL for suspicious attributes or untrusted signatures.
     * 
     * 
     */
    class HuntT9999 : public Hunt {

        public:
        HuntT9999();

        void Subtechnique006(IN CONST Scope& scope, OUT std::vector<std::shared_ptr<Detection>>& detections); 
        
        virtual std::vector<std::shared_ptr<Detection>> RunHunt(const Scope& scope) override;
        virtual std::vector<std::pair<std::unique_ptr<Event>, Scope>> GetMonitoringEvents() override;
    };
}
