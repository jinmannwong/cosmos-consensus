#pragma once
//------------------------------------------------------------------------------
//
//   Copyright 2018-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"

#include <map>
#include <set>
#include <unordered_map>
#include <vector>

namespace fetch {
namespace beacon {

class BeaconManager
{
public:
  using PrivateKey       = mcl::PrivateKey;
  using Signature        = mcl::Signature;
  using PublicKey        = mcl::PublicKey;
  using Generator        = mcl::Generator;
  using CabinetIndex     = uint32_t;
  using Share            = std::string;
  using Coefficient      = std::string;
  using ComplaintAnswer  = std::pair<CabinetIndex, std::pair<Share, Share>>;
  using ExposedShare     = std::pair<CabinetIndex, std::pair<Share, Share>>;
  using SharesExposedMap = std::unordered_map<CabinetIndex, std::pair<Share, Share>>;

  explicit BeaconManager();

  BeaconManager(BeaconManager const &) = delete;
  BeaconManager &operator=(BeaconManager const &) = delete;
  ~BeaconManager();

  void                     GenerateCoefficients();
  std::vector<Coefficient> GetCoefficients();
  std::pair<Share, Share>  GetOwnShares(CabinetIndex const &receiver);
  std::pair<Share, Share>  GetReceivedShares(CabinetIndex const &owner);
  void AddCoefficients(CabinetIndex const &from, std::vector<Coefficient> const &coefficients);
  void AddShares(CabinetIndex const &from, std::pair<Share, Share> const &shares);
  std::set<CabinetIndex> ComputeComplaints(std::set<CabinetIndex> const &coeff_received);
  bool VerifyComplaintAnswer(CabinetIndex const &from, ComplaintAnswer const &answer);
  void SetQual(std::set<CabinetIndex> qual);
  void ComputeSecretShare();
  std::vector<Coefficient> GetQualCoefficients();
  void AddQualCoefficients(CabinetIndex const &from, std::vector<Coefficient> const &coefficients);
  SharesExposedMap ComputeQualComplaints(std::set<CabinetIndex> const &coeff_received);
  CabinetIndex     VerifyQualComplaint(CabinetIndex const &from, ComplaintAnswer const &answer);
  void             ComputePublicKeys();
  void             AddReconstructionShare(CabinetIndex const &address);
  void             VerifyReconstructionShare(CabinetIndex const &from, ExposedShare const &share);
  bool             RunReconstruction();
  void NewCabinet(CabinetIndex cabinet_size, CabinetIndex threshold, CabinetIndex index);
  void Reset();

  /// Property methods
  /// @{
  bool                          InQual(CabinetIndex const &index) const;
  std::set<CabinetIndex> const &qual() const;
  CabinetIndex                  cabinet_index() const;
  CabinetIndex                  polynomial_degree() const;
  CabinetIndex                  cabinet_size() const;
  AeonExecUnit                  GetDkgOutput() const;
  ///}
  //

private:
  // What the DKG should return
  PrivateKey             secret_share_;       ///< Share of group private key (x_i)
  PublicKey              public_key_;         ///< Group public key (y)
  std::vector<PublicKey> public_key_shares_;  ///< Public keys of cabinet generated by DKG (v_i)
  std::set<CabinetIndex> qual_;               ///< Set of qualified members

  static Generator const & GetGroupG();
  static Generator const & GetGroupH();
  static PrivateKey const &GetZeroFr();

  CabinetIndex cabinet_size_;       ///< Size of cabinet
  CabinetIndex polynomial_degree_;  ///< Degree of polynomial in DKG
  CabinetIndex cabinet_index_;      ///< Index of our address in cabinet_

  // Temporary for DKG construction
  std::vector<PublicKey>               y_i;
  std::vector<std::vector<PrivateKey>> s_ij, sprime_ij;  ///< Secret shares
  std::vector<std::vector<PublicKey>>  C_ik;  ///< Verification vectors from cabinet members
  std::vector<std::vector<PublicKey>>  A_ik;  ///< Qual verification vectors
  std::vector<std::vector<PublicKey>>  g__s_ij;
  std::vector<PublicKey>               g__a_i;

  std::unordered_map<CabinetIndex, std::pair<std::set<CabinetIndex>, std::vector<PrivateKey>>>
      reconstruction_shares;  ///< Map from id of node_i in complaints to a pair <parties which
  ///< exposed shares of node_i, the shares that were exposed>

  void AddReconstructionShare(CabinetIndex const &                  from,
                              std::pair<CabinetIndex, Share> const &share);
};
}  // namespace beacon
}  // namespace fetch