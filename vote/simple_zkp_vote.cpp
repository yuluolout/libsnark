#include <iostream>
#include <fstream>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/profiling.hpp>

using namespace libsnark;
using namespace libff;

void generate_and_output_proof() {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

    // Initialize public parameters
    default_r1cs_ppzksnark_pp::init_public_params();

    // Create a protoboard
    protoboard<FieldT> pb;

    // Declare variables
    pb_variable<FieldT> voter_id;
    pb_variable<FieldT> candidate_number;

    // Allocate variables
    voter_id.allocate(pb, "voter_id");
    candidate_number.allocate(pb, "candidate_number");

    // Add constraints
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(voter_id, 1, voter_id), "voter_id constraint");
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(candidate_number, 1, candidate_number), "candidate_number constraint");

    // Set inputs
    pb.set_input_sizes(2);

    // Generate keys
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(pb.get_constraint_system());

    // Read input values from a file (proof.txt)
    std::ifstream proof_file("proof.txt");
    std::string voter_id_str, candidate_number_str;
    proof_file >> voter_id_str >> candidate_number_str;

    pb.val(voter_id) = FieldT(voter_id_str.c_str());
    pb.val(candidate_number) = FieldT(candidate_number_str.c_str());

    // Generate proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Output the proof to a file (proof_output.txt)
    std::ofstream proof_output_file("proof_output.txt");
    proof_output_file << proof;
    proof_output_file.close();

    // Output the verification key to a file (vk.txt)
    std::ofstream vk_file("vk.txt");
    vk_file << keypair.vk;
    vk_file.close();
}

void verify_proof() {
    typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

    // Read input values from a file (proof.txt)
    std::ifstream proof_file("proof.txt");
    std::string voter_id_str, candidate_number_str;
    proof_file >> voter_id_str >> candidate_number_str;

    // Create primary input
    r1cs_primary_input<FieldT> primary_input = {FieldT(voter_id_str.c_str()), FieldT(candidate_number_str.c_str())};

    // Read the verification key from a file (vk.txt)
    std::ifstream vk_file("vk.txt");
    r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk;
    vk_file >> vk;
    vk_file.close();

    // Read the proof from a file (proof_output.txt)
    std::ifstream proof_output_file("proof_output.txt");
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
    proof_output_file >> proof;
    proof_output_file.close();

    // Verify the proof
    const bool is_verified = r1cs_ppzksnark_verifier_strong_IC(vk, primary_input, proof);
    std::cout << "Vote verification result: " << (is_verified ? "PASS" : "FAIL") << std::endl;
}

int main() {
    // Generate and output proof
    generate_and_output_proof();

    // Verify the proof
    verify_proof();

    return 0;
}






