const releaseLink = document.querySelector("#release-link");

if (releaseLink && location.hostname.endsWith("github.io")) {
  const owner = location.hostname.replace(".github.io", "");
  const repo = location.pathname.split("/").filter(Boolean)[0];
  if (owner && repo) {
    releaseLink.href = `https://github.com/${owner}/${repo}/releases`;
  }
}
