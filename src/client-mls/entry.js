import * as mls from 'ts-mls';

// Export onto window.MLS for browser consumption
if (typeof window !== 'undefined') {
  window.MLS = mls;
}

export default mls;
export * from 'ts-mls';
