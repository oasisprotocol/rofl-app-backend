import { SiweMessage } from 'siwe';
import { getAddress } from 'ethers';
import { Buffer } from 'buffer';
window.Buffer = Buffer;

const domain = "localhost:3000";
const backend = "http://localhost:8899";

// SIWE Login test.
const loginBtn = document.getElementById("login");
const logoutBtn = document.getElementById("logout");
const output = document.getElementById("output");

loginBtn.onclick = async () => {
  const [address] = await window.ethereum.request({ method: "eth_requestAccounts" });
  const checksummed = getAddress(address);

  const nonceRes = await fetch(`${backend}/auth/nonce?address=${checksummed}`);
  if (!nonceRes.ok) {
    output.textContent = "Failed to fetch nonce";
    return;
  }
  const { nonce } = await nonceRes.json();

  const siweMsg = new SiweMessage({
    domain: "localhost",
    address: checksummed,
    statement: "Sign in to localhost",
    uri: "http://" + domain,
    version: "1",
    chainId: 1,
    issuedAt: new Date().toISOString(),
    nonce
  });

  const message = siweMsg.prepareMessage();
  const signature = await window.ethereum.request({
    method: "personal_sign",
    params: [message, address],
  });

  const res = await fetch(`${backend}/auth/login?sig=${signature}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });

  const data = await res.json();
  if (!data.token) {
    output.textContent = "Login failed: " + JSON.stringify(data);
    return;
  }

  localStorage.setItem("jwt", data.token);
  await loadMe();
};

logoutBtn.onclick = () => {
  localStorage.removeItem("jwt");
  location.reload();
};

async function loadMe() {
  const token = localStorage.getItem("jwt");
  if (!token) return;

  const meRes = await fetch(`${backend}/me`, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (meRes.ok) {
    const text = await meRes.text();
    output.textContent = "Authenticated:\n" + text;
    loginBtn.style.display = "none";
    logoutBtn.style.display = "inline-block";
  } else {
    localStorage.removeItem("jwt");
  }
}

// Artifacts test.
const uploadBtn = document.getElementById("upload-artifact");
const downloadBtn = document.getElementById("download-artifact");

uploadBtn.onclick = async () => {
  const fileInput = document.getElementById("artifact-file");
  const id = document.getElementById("artifact-id").value.trim();
  const file = fileInput.files[0];
  const out = document.getElementById("artifact-output");

  if (!id || !file) {
    out.textContent = "Missing ID or file.";
    return;
  }

  const token = localStorage.getItem("jwt");
  const res = await fetch(`${backend}/artifacts/${id}`, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/octet-stream",
    },
    body: file
  });

  out.textContent = res.ok ? "Upload OK" : `Upload failed: ${res.status}`;
};

downloadBtn.onclick = async () => {
  const id = document.getElementById("artifact-id").value.trim();
  const out = document.getElementById("artifact-output");

  if (!id) {
    out.textContent = "Missing ID.";
    return;
  }

  const token = localStorage.getItem("jwt");
  const res = await fetch(`${backend}/artifacts/${id}`, {
    headers: {
      "Authorization": `Bearer ${token}`,
    },
  });
  if (!res.ok) {
    out.textContent = `Download failed: ${res.status}`;
    return;
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = id;
  a.click();
  URL.revokeObjectURL(url);
  out.textContent = "Download triggered.";
};

window.addEventListener("DOMContentLoaded", loadMe);

// ROFL Build test.
const buildBtn = document.getElementById("start-build");
const spinner = document.getElementById("spinner");

buildBtn.onclick = async () => {
  spinner.style.display = "block";  // show spinner when starting

  const manifestFile = document.getElementById("rofl-manifest").files[0];
  const composeFile = document.getElementById("compose-file").files[0];
  const buildOut = document.getElementById("build-output");

  if (!manifestFile || !composeFile) {
    buildOut.textContent = "Please select both rofl.yaml and compose.yaml files.";
    return;
  }

  const manifestText = await manifestFile.text();
  const composeText = await composeFile.text();

  const token = localStorage.getItem("jwt");
  const res = await fetch(`${backend}/rofl/build`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      manifest: manifestText,
      compose: composeText,
    }),
  });

  if (!res.ok) {
    buildOut.textContent = `Build start failed: ${res.status}`;
    return;
  }

  const { task_id } = await res.json();
  buildOut.textContent = `Build started. Task ID: ${task_id}`;

  // Poll for results every 3 seconds
  const poll = async () => {
    const statusRes = await fetch(`${backend}/rofl/build/${task_id}/results`, {
      headers: {
        "Authorization": `Bearer ${token}`,
      },
    });

    if (statusRes.status === 202) {
      setTimeout(poll, 3000);
      return;
    }
    if (statusRes.status === 404) {
      buildOut.textContent = "Build not found";
      return;
    }

    spinner.style.display = "none";

    if (!statusRes.ok) {
      buildOut.textContent = `Error fetching results: ${statusRes.status}`;
      return;
    }

    const result = await statusRes.json();

    let manifestText = "(no manifest)";
    try {
      if (result.manifest) {
        manifestText = atob(result.manifest);
      }
    } catch {
      manifestText = "[invalid base64 manifest]";
    }


    const summary = {
      oci_reference: result.oci_reference,
      manifest_hash: result.manifest_hash,
      err: result.err,
    };

    buildOut.textContent = "Build complete:\n\n" +
      "Summary:\n" + JSON.stringify(summary, null, 2) + "\n\n" +
      "Manifest:\n" + manifestText + "\n\n" +
      "Logs:\n" + result.logs;
  };

  setTimeout(poll, 3000);
};

