#pragma once

#include <string>
#include "nutcpp/payment/payment_request.h"

namespace nutcpp::payment {

// NUT-18: CBOR + base64url encoder for payment requests.
// Produces "creqA" + base64url(CBOR(PaymentRequest)).
// Also provides parse() which dispatches creqA (and creqB when available).
class PaymentRequestEncoder {
public:
    // Encode a PaymentRequest to "creqA..." string
    static std::string encode(const PaymentRequest& request);

    // Decode a "creqA..." string to PaymentRequest
    static PaymentRequest decode(const std::string& payload);

    // Parse any payment request format (creqA, creqB in future)
    static PaymentRequest parse(const std::string& creq);
};

} // namespace nutcpp::payment
