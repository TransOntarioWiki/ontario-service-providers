import React, { useState, useMemo, useEffect } from "react";
import Modal from "react-overlays/Modal";
import { useMe, postReview, putReview, useReviews } from "./api";
import Avatar from "./Avatar";

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
  const [myReview, setMyReview] = useState("");
  const [myRating, setMyRating] = useState(5);

  const reviews = useMemo(() => {
    if (!reviewData.isLoading && reviewData.data && reviewData.data.pages) {
      return reviewData.data.pages.map((page) => page?.data || []).flat();
    }
    return [];
  }, [reviewData.isLoading, reviewData.data]);

  // TODO: make sure mine shows up even if there are multiple pages of reviews
  const myExistingReviewData = reviews.find(
    (review) => review.discord_user_id === me.data?.id
  );
  const myExistingReview = myExistingReviewData?.text ?? "";
  const myExistingRating = myExistingReviewData?.score ?? 5;

  // reset when changing providers or when review data
  useEffect(() => {
    setMyReview(myExistingReview);
    setMyRating(myExistingRating);
  }, [provider?.id, myExistingReview, myExistingRating]);

  if (!provider) {
    return null;
  }
  return (
    <Modal
      show={provider != null}
      onHide={onClose}
      renderBackdrop={renderBackdrop}
      className="fixed top-1/2 left-1/2 p-4 rounded-lg bg-white drop-shadow-md -translate-x-1/2 -translate-y-1/2 min-width- max-h-full overflow-y-scroll"
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
        </div>
        <h2 className="pt-4 text-2xl">Reviews</h2>
        {me.data ? (
          <div>
            <div className="flex">
              <Avatar
                id={me.data.id}
                avatar={me.data.avatar}
                className="h-16 mr-4"
              />
              <textarea
                className="border rounded border-black w-full"
                value={myReview}
                onChange={(ev) => {
                  setMyReview(ev.target.value);
                }}
              />
            </div>
            <div className="flex py-2">
              <div className="flex-grow" />
              Rating out of 5:
              <input
                min="1"
                max="5"
                type="number"
                value={myRating}
                onChange={(ev) => {
                  setMyRating(ev.target.valueAsNumber);
                }}
                className="ml-2 mr-8 border border-black rounded-md w-14 h-6"
              />
              <button
                className="bg-blue-500 hover:bg-blue-700 rounded-md text-white py-1 px-2 mt-2"
                onClick={(ev) => {
                  ev.preventDefault();
                  if (myExistingReviewData) {
                    putReview(provider.id, me.data.id, myReview, myRating);
                  } else {
                    postReview(provider.id, myReview, myRating);
                  }
                }}
              >
                Submit
              </button>
            </div>
          </div>
        ) : null}
        {reviews.map((review) =>
          review.discord_user_id === me.data?.id ? null : (
            <div key={review.discord_user_id}>
              <div className="flex">
                <Avatar
                  id={review.discord_user_id}
                  avatar={review.avatar}
                  className="h-16 mr-4"
                />
                <div className="border rounded border-black w-full">
                  {review.text}
                </div>
              </div>
              <div className="flex py-2">
                <div className="flex-grow" />
                By {review.username}#{review.discriminator} | Rating out of 5:
                {review.score}
              </div>
            </div>
          )
        )}
        {reviews.length === 0 ? <div>No reviews</div> : null}
      </div>
    </Modal>
  );
};

export default ProviderOverlay;
