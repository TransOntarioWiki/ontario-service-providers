import Modal from "react-overlays/Modal";

const renderBackdrop = props => (
  <div {...props} className="w-screen h-screen bg-black/30 fixed top-0 left-0" />
);

const rhoUrl = slug => `https://www.rainbowhealthontario.ca/service-provider-directory/${slug}/`;

const ProviderOverlay = ({ onClose, provider }) => {
  if (!provider) {
    return null;
  }
  return (
    <Modal
      show={provider}
      onHide={onClose}
      renderBackdrop={renderBackdrop}
      className="fixed top-1/2 left-1/2 p-4 rounded-lg bg-white drop-shadow-md -translate-x-1/2 -translate-y-1/2 min-width-"
    >
      <div className="flex flex-col">
        <h1 className="text-3xl">{provider.name}</h1>
        {provider.slug && (
          <a
            className="self-end text-blue-500"
            href={rhoUrl(provider.slug)}
            target="_blank"
            rel="noopener noreferrer"
          >
            View on RHO
          </a>
        )}
        <span>Services: {provider.services?.join(", ")}</span>
        <span>Specializes in: {provider.specializes_in?.join(", ")}</span>
        <div className="flex mt-6 gap-2 flex-col lg:flex-row">
          <div className="w-full lg:w-2/3">
            <p className="w-96">{provider.description}</p>
          </div>
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
                >{provider.email}</a>
              </span>
            )}
            {provider.website && (
              <a
                className="text-blue-500 underline"
                href={provider.website}
                target="_blank"
                rel="noopener noreferrer"
              >{provider.website}</a>
            )}
            {provider.house_of_operation && (
              <span>Hours: {provider.hours_of_operation}</span>
            )}
            {provider.address.split("\n").map(
              addressSegment => <p>{addressSegment}</p>)}
          </div>
        </div>
      </div>
    </Modal>
  );
};

export default ProviderOverlay;
