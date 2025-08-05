//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*

Example for CKKS bootstrapping with full packing

*/

#define PROFILE

#include "openfhe.h"

#include <iostream>
#include <vector>

using namespace lbcrypto;

void TestSparseEncapsulation();

int main(int argc, char* argv[]) {
    TestSparseEncapsulation();
}

void TestSparseEncapsulation() {
    SecretKeyDist secretKeyDist  = SPARSE_TERNARY;
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    uint32_t dcrtBits            = 50;
    uint32_t firstMod            = 60;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(secretKeyDist);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    std::vector<uint32_t> levelBudget = {4, 4};

    uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    auto keyPair = cc->KeyGen();

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 0.375, 0.675, 0.125, 0.925};
    size_t encodedLength  = x.size();

    // We start with a depleted ciphertext that has used up all of its levels.
    auto ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    ptxt->SetLength(encodedLength);
    auto ctxt = cc->Encrypt(keyPair.publicKey, ptxt);

    std::cout << "Input: " << ptxt << std::endl;

    // Test KeySwitchSparse(keyPair.secretKey, ctxt)
    const auto cryptoParams =
        std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(keyPair.secretKey->GetCryptoParameters());
    const auto paramsQ = cryptoParams->GetElementParams();

    DCRTPoly::TugType tug;
    DCRTPoly sNew(tug, paramsQ, Format::EVALUATION, 32);

    auto skNew = std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);
    skNew->SetPrivateElement(std::move(sNew));

    auto evalKey = FHECKKSRNS::KeySwitchGenSparse(keyPair.secretKey, skNew);

    auto ctresult = FHECKKSRNS::KeySwitchSparse(ctxt, evalKey);

    Plaintext result;
    cc->Decrypt(skNew, ctresult, &result);
    result->SetLength(8);

    std::cout << "Result after decryption = " << result << std::endl;
}
