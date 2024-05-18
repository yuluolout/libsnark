#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/utils.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

using namespace libsnark;
using namespace libff;

// Function to read the proof from a binary file
std::vector<uint8_t> read_proof(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << filename << std::endl;
        exit(EXIT_FAILURE);
    }
    std::vector<uint8_t> proof_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return proof_data;
}

int main() {
    libff::start_profiling();

    // Initialize the default parameters for the elliptic curve
    default_ec_pp::init_public_params();

    // Create a protoboard
    protoboard<Fr<default_ec_pp>> pb;

    // Define constraints here
    // Example constraints (you should replace this with your actual constraints)
    pb_variable<Fr<default_ec_pp>> a, b, c;
    a.allocate(pb, "a");
    b.allocate(pb, "b");
    c.allocate(pb, "c");

    pb.val(a) = 3;
    pb.val(b) = 4;
    pb.val(c) = 12;

    pb.add_r1cs_constraint(r1cs_constraint<Fr<default_ec_pp>>(a, b, c));

    // Generate keypair
    const r1cs_ppzksnark_keypair<default_ec_pp> keypair = r1cs_ppzksnark_generator<default_ec_pp>(pb.get_constraint_system());

    // Read proof from proof.txt
    std::vector<uint8_t> proof_data = read_proof("proof.txt");

    // Deserialize the proof
    r1cs_ppzksnark_proof<default_ec_pp> proof;
    std::istringstream proof_stream(std::string(proof_data.begin(), proof_data.end()));
    proof_stream >> proof;

    // Create the primary input (public input)
    const r1cs_primary_input<Fr<default_ec_pp>> primary_input = pb.primary_input();

    // Verify the proof
    bool result = r1cs_ppzksnark_verifier_strong_IC(keypair.vk, primary_input, proof);

    std::cout << "Vote verification result: " << (result ? "PASS" : "FAIL") << std::endl;

    return 0;
}
