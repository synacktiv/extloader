console.log("Hello from service worker !")

chrome.cookies.getAll({}, (cookies) => {
    console.log('All cookies:', cookies);
});
  