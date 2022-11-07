const ProviderFeeDetails = ({ provider }) => (
  <div className="flex flex-col p-2 border border-black rounded min-w-fit">
    <span className="self-center underline">Service Details</span>
    {provider.hours_of_operation && (
      <span className="text-wrap">Hours: {provider.hours_of_operation}</span>
    )}
    {provider.referral_requirements?.length ? (
      <span>
        Referral Requirements: {provider.referral_requirements.join(", ")}
      </span>
    ) : null}
    {provider.fees?.length ? (
      <span>Fees: {provider.fees.join(", ")}</span>
    ) : null}
    {provider.fee_info && <span>{provider.fee_info}</span>}
  </div>
);

export default ProviderFeeDetails;
