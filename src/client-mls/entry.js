import * as mls from 'ts-mls';
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js';

const extendedMls = {
  ...mls,
  makeKeyPackageRef,
};

// Export onto window.MLS for browser consumption
if (typeof window !== 'undefined') {
  window.MLS = extendedMls;
}

export default extendedMls;
export * from 'ts-mls';
export { makeKeyPackageRef };

