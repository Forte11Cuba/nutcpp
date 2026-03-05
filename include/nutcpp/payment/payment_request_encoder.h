#pragma once

#include <string>
#include "nutcpp/payment/payment_request.h"

namespace nutcpp::payment {

// NUT-18: CBOR + base64url encoder for payment requests.
// Produces "creqA" + base64url(CBOR(PaymentRequest)).
// parse() dispatches creqA and creqB (via PaymentRequestBech32Encoder).
class PaymentRequestEncoder {
public:
    // Encode a PaymentRequest to "creqA..." string
    static std::string encode(const PaymentRequest& request);

    // Decode base64url(CBOR) payload (without "creqA" prefix) to PaymentRequest
    static PaymentRequest decode(const std::string& payload);

    // Parse any payment request format (creqA or creqB)
    static PaymentRequest parse(const std::string& creq);
};

} // namespace nutcpp::payment
