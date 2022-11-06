import React, { useMemo } from "react";
import { useParams } from "react-router-dom";

import { useMe, useReviews, useProvider } from "./api";
import Review from "./Review";
import ReviewForm from "./ReviewForm";
import PageChrome from "./PageChrome";
import ProviderContactDetails from "./ProviderContactDetails";
import { Link } from "react-router-dom";

const rhoUrl = (slug) =>
  `https://www.rainbowhealthontario.ca/service-provider-directory/${slug}/`;

const ProviderOverlay = () => {
  const me = useMe();
  const { providerSlug } = useParams();
  const { data: provider } = useProvider(providerSlug);
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
    <PageChrome>
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
        {me.data ? (
          <Link
            to={`/provider/${provider.slug}/edit`}
            className="text-blue-500 self-end"
          >
            Edit
          </Link>
        ) : null}
        <span>Services: {provider.services?.join(", ")}</span>
        <span>Specializes in: {provider.specializes_in?.join(", ")}</span>
        <div className="flex mt-6 gap-2 flex-col lg:flex-row">
          <div className="w-full lg:w-2/3">
            <p className="w-full lg:w-96">{provider.description}</p>
          </div>
          <ProviderContactDetails provider={provider} />
        </div>
        <h2 className="pt-4 pb-2 text-2xl">Reviews</h2>
        {me.data ? (
          <ReviewForm
            key={provider.id}
            myReview={myExistingReviewData}
            provider={provider}
          />
        ) : null}
        {reviews.map((review) =>
          review.discord_user_id === me.data?.id || !review.text ? null : (
            <Review key={review.id} review={review} />
          )
        )}
        {reviews.length === 0 ? <div>No reviews</div> : null}
      </div>
    </PageChrome>
  );
};

export default ProviderOverlay;
