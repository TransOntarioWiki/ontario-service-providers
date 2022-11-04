import React, { useMemo } from "react";
import Modal from "react-overlays/Modal";
import { useMe, useReviews } from "./api";
import Review from "./Review";
import ReviewForm from "./ReviewForm";
import ProviderContactDetails from "./ProviderContactDetails";

const renderBackdrop = (props) => (
  <div
    {...props}
    className="w-screen h-screen bg-black/30 fixed top-0 left-0"
  />
);

const rhoUrl = (slug) =>
  `https://www.rainbowhealthontario.ca/service-provider-directory/${slug}/`;

const ProviderOverlay = ({ onClose, provider }) => {
  const me = useMe();
  const reviewData = useReviews(provider?.id);

  const reviews = useMemo(() => {
    if (!reviewData.isLoading && reviewData.data && reviewData.data.pages) {
      return reviewData.data.pages.map((page) => page?.data || []).flat();
    }
    return [];
  }, [reviewData.isLoading, reviewData.data]);

  const myExistingReviewData = reviews.find(
    (review) => review.discord_user_id === me.data?.id
  );

  if (!provider) {
    return null;
  }
  return (
    <Modal
      show={provider != null}
      onHide={onClose}
      renderBackdrop={renderBackdrop}
      className="fixed top-1/2 left-1/2 p-4 rounded-lg bg-white drop-shadow-md -translate-x-1/2 -translate-y-1/2 min-width-0 max-h-full overflow-y-auto box-border"
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
          <ProviderContactDetails provider={provider} />
        </div>
        <h2 className="pt-4 text-2xl">Reviews</h2>
        {me.data ? <ReviewForm key={provider.id} myReview={myExistingReviewData} provider={provider} /> : null}
        {reviews.map((review) => review.discord_user_id === me.data?.id ? null : <Review review={review} />)}
        {reviews.length === 0 ? <div>No reviews</div> : null}
      </div>
    </Modal>
  );
};

export default ProviderOverlay;
