import { stringify } from 'query-string';
import {
  QueryParams,
  PersistableQueryParams,
} from '@/shared/model/QueryParams';
import { AllRoutes } from './routeUtils';

export const getPersistableQueryParams = (
  params: QueryParams,
): PersistableQueryParams => ({
  returnUrl: params.returnUrl,
  clientId: params.clientId,
  ref: params.ref,
  refViewId: params.refViewId,
});

export const addQueryParamsToPath = (
  path: AllRoutes,
  params: QueryParams,
  overrides?: Partial<QueryParams>,
): string => {
  return addQueryParamsToStringPath(path, params, overrides);
};

//This takes a non-typed url string and adds query parameters
//This should only be used when you have a path that is dynamically generated ie from another input parameter
//You should use addQueryParamsToPath for all typed internal application urls

export const addQueryParamsToStringPath = (
  path: string,
  params: QueryParams,
  overrides?: Partial<QueryParams>,
): string => {
  const divider = path.includes('?') ? '&' : '?';
  const queryString = stringify(
    { ...getPersistableQueryParams(params), ...overrides },
    {
      skipNull: true,
      skipEmptyString: true,
    },
  );
  return `${path}${divider}${queryString}`;
};

export const buildQueryParamsString = (
  params: QueryParams,
  overrides?: Partial<QueryParams>,
): string => {
  const queryString = stringify(
    { ...getPersistableQueryParams(params), ...overrides },
    {
      skipNull: true,
      skipEmptyString: true,
    },
  );
  return `?${queryString}`;
};
