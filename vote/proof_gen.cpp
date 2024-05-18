#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <sstream>
#include <iostream>
#include <fstream>

using namespace libsnark;
using namespace std;

// Function to serialize proof to string
string serialize_proof(const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp>& proof) {
    stringstream ss;
    ss << proof;
    return ss.str();
}

// Function to deserialize proof from string
r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> deserialize_proof(const string& str) {
    stringstream ss(str);
    r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof;
    ss >> proof;
    return proof;
}

// Function to generate and output proof
void generate_and_output_proof() {
    // Initialize the curve parameters
    default_r1cs_ppzksnark_pp::init_public_params();

    // Example constraint system
    protoboard<libff::Fr<default_r1cs_ppzksnark_pp>> pb;
    pb_variable<libff::Fr<default_r1cs_ppzksnark_pp>> x;
    pb_variable<libff::Fr<default_r1cs_ppzksnark_pp>> y;

    x.allocate(pb, "x");
    y.allocate(pb, "y");

    pb.add_r1cs_constraint(r1cs_constraint<libff::Fr<default_r1cs_ppzksnark_pp>>(x, y, 1), "constraint");

    pb.val(x) = 1;
    pb.val(y) = 2;

    const r1cs_constraint_system<libff::Fr<default_r1cs_ppzksnark_pp>> constraint_system = pb.get_constraint_system();

    // Generate keypair
    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    // Create proof
    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    // Serialize proof
    string serialized_proof = serialize_proof(proof);

    // Output serialized proof to a file
    ofstream proof_file("proof_gen.txt");
    proof_file << serialized_proof;
    proof_file.close();

    cout << "Proof generated and written to proof.txt" << endl;
}

int main() {
    generate_and_output_proof();
    return 0;
}
