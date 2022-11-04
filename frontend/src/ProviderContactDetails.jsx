const ProviderContactDetails = ({ provider }) => (
  <div className="flex flex-col p-2 border border-black rounded min-w-fit w-3/4 lg:w-1/3 lg:justify-self-stretch self-center">
    <span className="self-center underline">Contact</span>
    {provider.phone && <span>Phone: {provider.phone}</span>}
    {provider.email && (
      <span>
        Email:&nbsp;
        <a
          className="text-blue-500 underline"
          href={`mailto:${provider.email}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          {provider.email}
        </a>
      </span>
    )}
    {provider.website && (
      <a
        className="text-blue-500 underline"
        href={provider.website}
        target="_blank"
        rel="noopener noreferrer"
      >
        {provider.website}
      </a>
    )}
    {provider.house_of_operation && (
      <span>Hours: {provider.hours_of_operation}</span>
    )}
    {provider.address?.split("\n").map((addressSegment, i) => (
      <p key={i}>{addressSegment}</p>
    ))}
  </div>
);

export default ProviderContactDetails;
