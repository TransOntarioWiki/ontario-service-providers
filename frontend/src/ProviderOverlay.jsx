import React, { useMemo } from "react";
import { useParams } from "react-router-dom";

import { useMe, useReviews, useProvider } from "./api";
import Review from "./Review";
import ReviewForm from "./ReviewForm";
import PageChrome from "./PageChrome";
import ProviderContactDetails from "./ProviderContactDetails";
import ProviderFeeDetails from "./ProviderFeeDetails";
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
      <div className="flex flex-col m-4">
        <h1 className="text-3xl text-center">{provider.name}</h1>
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
        <div className="flex flex-col border-b border-black pb-2">
          <span>
            <b>Services:</b> {provider.services?.join(", ")}
          </span>
          <span>
            <b>Specializes in:</b> {provider.specializes_in?.join(", ")}
          </span>
          {provider.assessments_provided && (
            <span>
              <b>Assessments Provided:</b> {provider.assessments_provided}
            </span>
          )}
        </div>
        <p className="mt-4 mb-4 w-full">{provider.description}</p>
        <div className="flex flex-wrap gap-2 items-stretch">
          <ProviderContactDetails provider={provider} />
          <ProviderFeeDetails provider={provider} />
        </div>
        <h2 className="pt-4 pb-2 text-2xl">Reviews</h2>
        {me.data ? (
          <ReviewForm
            key={provider.id}
            myReview={myExistingReviewData}
            provider={provider}
          />
        ) : null}
        {reviews.map((review) => !review.text ? null : (
          <Review key={review.id} review={review} />
        ))}
        {reviews.length === 0 ? <div>No reviews</div> : null}
      </div>
    </PageChrome>
  );
};

export default ProviderOverlay;
