#pragma once

#include <string>
#include "nutcpp/payment/payment_request.h"

namespace nutcpp::payment {

// NUT-26: Bech32m TLV encoder for payment requests.
// Produces uppercase "CREQB1..." Bech32m strings for QR compatibility.
class PaymentRequestBech32Encoder {
public:
    // Encode a PaymentRequest to "CREQB1..." Bech32m string (uppercase)
    static std::string encode(const PaymentRequest& request);

    // Decode a Bech32m TLV payment request (accepts uppercase or lowercase)
    static PaymentRequest decode(const std::string& creqb);
};

} // namespace nutcpp::payment
