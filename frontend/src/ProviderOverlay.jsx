import Modal from "react-overlays/Modal";

const renderBackdrop = props => (
  <div {...props} className="w-screen h-screen bg-black/30 fixed top-0 left-0" />
)

const ProviderOverlay = ({ onClose, provider }) => {
  return (
    <Modal
      show={provider}
      onHide={onClose}
      renderBackdrop={renderBackdrop}
      className="fixed top-1/2 left-1/2 p-4 rounded-lg bg-white drop-shadow-md -translate-x-1/2 -translate-y-1/2"
    >
      <div>Provider details!</div>
    </Modal>
  );
};

export default ProviderOverlay;
