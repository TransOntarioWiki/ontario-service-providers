import React, { useState } from "react";
import PageChrome from "./PageChrome";
import { useNavigate, useParams } from "react-router-dom";
import {
  useProvider,
  useReferralRequirements,
  useLanguages,
  useFees,
  useServices,
  useCharacteristics,
  patchProviders,
  createProvider,
} from "./api";
import { Form, Field } from "react-final-form";

function Pill({ label, selected, onClick }) {
  const selectedClasses =
    "text-white bg-blue-500 hover:bg-blue-700 hover:drop-shadow-md border-blue-500 hover:border-blue-700";
  const unselectedClasses =
    "text-blue-500 hover:text-blue-700 border-pink-500 hover:border-pink-700 ";
  const baseClasses =
    "mr-1 mb-1 border py-1 px-3 rounded-full text-sm duration-100";

  const className = selected
    ? baseClasses + selectedClasses
    : baseClasses + unselectedClasses;

  return (
    <>
      <button className={className} onClick={onClick}>
        {label}
      </button>
    </>
  );
}

function MultiSelect({ useOptions, optionKey, className, input }) {
  const options = useOptions();
  if (options.status !== "success") {
    return null;
  }
  const keys = options.data.map((option) => option[optionKey]);
  const value = input.value ?? [];

  return (
    <div className={className}>
      {keys.map((key) => (
        <Pill
          key={key}
          label={key}
          selected={value.includes(key)}
          onClick={(ev) => {
            ev.preventDefault();
            if (value.includes(key)) {
              input.onChange(value.filter((v) => v !== key));
            } else {
              input.onChange([...value, key]);
            }
          }}
        />
      ))}
    </div>
  );
}

function EditProvider() {
  const { providerSlug } = useParams();
  const providerData = useProvider(providerSlug);
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  if (providerData.isLoading) {
    return (
      <PageChrome>
        <div className="flex-grow" />
      </PageChrome>
    );
  }

  if (providerData.isError) {
    return (
      <PageChrome>
        <div className="flex-grow">
          <h1 className="text-3xl mb-8 p-4">Could not load this provider.</h1>
        </div>
      </PageChrome>
    );
  }

  if (!providerData.data && providerSlug) {
    return (
      <PageChrome>
        <div className="flex-grow">
          <h1 className="text-3xl mb-8 p-4">This provider does not exist.</h1>
        </div>
      </PageChrome>
    );
  }

  return (
    <PageChrome>
      <div className="p-4 flex flex-col w-full h-full relative flex-grow max-w-6xl mx-auto">
        <h1 className="text-3xl mb-8">
          {providerSlug ? `Edit ${providerSlug}` : "Create new Provider"}
        </h1>
        <Form
          initialValues={providerData.data}
          onSubmit={(data) => {
            if (data.accessibility_available === true) {
              data.accessibility_available = 1;
            } else if (data.accessibility_available === false) {
              data.accessibility_available = 0;
            }

            setError("Loading...");

            if (providerSlug) {
              patchProviders(data).then((res) => {
                if (res.status === 200) {
                  navigate(`/provider/${providerSlug}`);
                } else {
                  res.text().then((text) => setError(text));
                }
              });
            } else {
              createProvider(data).then((res) => {
                if (res.status === 201) {
                  navigate(`/provider/${data.slug}`);
                } else {
                  res.text().then((text) => setError(text));
                }
              });
            }
          }}
        >
          {(props) => (
            <form onSubmit={props.handleSubmit}>
              <div className="grid grid-cols-[120px_1fr]">
                <label className="self-center text-right">Name</label>
                <Field
                  name="name"
                  component="input"
                  className="m-2 border-black border-b "
                />

                {providerSlug == null ? (
                  <>
                    <label className="self-center text-right">Slug</label>
                    <div>
                      <Field
                        name="slug"
                        component="input"
                        className="m-2 border-black border-b "
                      />
                      (in URL)
                    </div>
                  </>
                ) : null}

                <label className="pt-3 text-right">Address</label>
                <Field
                  name="address"
                  component="textarea"
                  className="m-2 border-black border-b px-2 py-1 resize-none h-32"
                />

                <label className="self-center text-right">FSA</label>
                <div>
                  <Field
                    name="fsa"
                    component="input"
                    className="m-2 border-black border-b"
                  />
                  (First three digits of postal code)
                </div>

                <label className="self-center text-right">Email</label>
                <Field
                  name="email"
                  component="input"
                  className="m-2 border-black border-b "
                />

                <label className="self-center text-right">Assessments</label>
                <Field
                  name="assessments_provided"
                  component="input"
                  className="m-2 border-black border-b "
                />

                <label className="pt-3 text-right">Description</label>
                <Field
                  name="description"
                  component="textarea"
                  className="m-2 border-black border-b px-2 py-1 resize-none h-52"
                />

                <label className="pt-3 text-right">Hours</label>
                <Field
                  name="hours_of_operation"
                  component="textarea"
                  className="m-2 border-black border-b px-2 py-1 resize-none h-32"
                />

                <label className="self-center text-right">Phone</label>
                <Field
                  name="phone"
                  component="input"
                  className="m-2 border-black border-b"
                />

                <label className="pt-3 text-right">Other locations</label>
                <Field
                  name="satellite_locations"
                  component="textarea"
                  className="m-2 border-black px-2 py-1 border-b resize-none h-32"
                />

                <label className="pt-3 text-right">Submitted by</label>
                <Field
                  name="submitted_by"
                  component="textarea"
                  className="m-2 px-2 py-1 border-black border-b resize-none h-32"
                />

                <label className="self-center text-right">Accessibility</label>
                <Field
                  name="accessibility_available"
                  component="input"
                  type="checkbox"
                  className="m-2 border-black border-b mr-auto"
                />

                <label className="self-center text-right">Website</label>
                <Field
                  name="website"
                  component="input"
                  className="m-2 border-black border-b"
                />

                <label className="self-center text-right">Languages</label>
                <Field
                  name="languages"
                  component={MultiSelect}
                  useOptions={useLanguages}
                  optionKey="language"
                  className="m-2"
                />

                <label className="self-center text-right">Specializes in</label>
                <Field
                  name="specializes_in"
                  component={MultiSelect}
                  useOptions={useCharacteristics}
                  optionKey="characteristic"
                  className="m-2"
                />

                <label className="self-center text-right">Referral</label>
                <Field
                  name="referral_requirements"
                  component={MultiSelect}
                  useOptions={useReferralRequirements}
                  optionKey="requirement"
                  className="m-2"
                />

                <label className="self-center text-right">Fees</label>
                <Field
                  name="fees"
                  component={MultiSelect}
                  useOptions={useFees}
                  optionKey="fee"
                  className="m-2"
                />

                <label className="pt-3 text-right">More fee details</label>
                <Field
                  name="fee_info"
                  component="textarea"
                  className="m-2 px-2 py-1 border-black border-b resize-none h-32"
                />

                <label className="self-center text-right">Services</label>
                <Field
                  name="services"
                  component={MultiSelect}
                  useOptions={useServices}
                  optionKey="name"
                  className="m-2"
                />
              </div>
              {error && <pre>{error}</pre>}

              <button
                type="submit"
                className="block mx-auto bg-blue-500 hover:bg-blue-700 rounded-md text-white py-1 px-2 mt-2"
              >
                Submit
              </button>
            </form>
          )}
        </Form>
      </div>
    </PageChrome>
  );
}

export default EditProvider;
