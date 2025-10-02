console.log("Hello from content-script !");

const dumpStorage = (storage) =>
  [...Array(storage.length).keys()]
    .map(i => {
      const key = storage.key(i);
      return { key, value: storage.getItem(key) };
    });

console.log("localStorage contents:", dumpStorage(localStorage));
console.log("sessionStorage contents:", dumpStorage(sessionStorage));
