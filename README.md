const ADMIN_EMAIL = "admin@mastercrosscharityfoundation.com";

const SESSION_DURATION = 24 * 60 * 60 * 1000;
const MAX_IMAGE_SIZE = 5 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp"
];

const R2_PREFIX = "website-images/";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(env)
        });
      }

      /*
       * Public API
       */

      if (
        url.pathname === "/api/members" &&
        request.method === "GET"
      ) {
        return getPublicMembers(env);
      }

      if (
        url.pathname === "/api/contact" &&
        request.method === "POST"
      ) {
        return createMessage(request, env);
      }

      if (
        url.pathname.startsWith("/api/images/")
      ) {
        return serveImage(request, env, url);
      }

      /*
       * Authentication
       */

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return login(request, env);
      }

      if (
        url.pathname === "/api/logout" &&
        request.method === "POST"
      ) {
        return logout(request, env);
      }

      /*
       * Protected admin API
       */

      if (
        url.pathname.startsWith("/api/admin/")
      ) {
        const session =
          await authenticate(request, env);

        if (!session) {
          return json(
            { error: "Unauthorized" },
            401,
            env
          );
        }

        return handleAdminAPI(
          request,
          env,
          url
        );
      }

      /*
       * Admin interface
       */

      if (
        url.pathname === "/admin" ||
        url.pathname === "/admin/"
      ) {
        return new Response(
          ADMIN_HTML,
          {
            headers: {
              "Content-Type":
                "text/html; charset=UTF-8",
              "Cache-Control":
                "no-store"
            }
          }
        );
      }

      return new Response(
        "MasterCross Charity Foundation Admin Backend",
        {
          status: 200,
          headers: {
            "Content-Type":
              "text/plain; charset=UTF-8"
          }
        }
      );

    } catch (error) {
      console.error(error);

      return json(
        {
          error:
            "An internal server error occurred."
        },
        500,
        env
      );
    }
  }
};


/* =========================================================
   AUTHENTICATION
========================================================= */

async function login(request, env) {
  if (!env.ADMIN_PASSWORD) {
    return json(
      {
        error:
          "ADMIN_PASSWORD secret has not been configured."
      },
      500,
      env
    );
  }

  const body =
    await request.json().catch(() => null);

  if (!body) {
    return json(
      {
        error: "Invalid request."
      },
      400,
      env
    );
  }

  const email =
    String(body.email || "")
      .trim()
      .toLowerCase();

  const password =
    String(body.password || "");

  if (
    email !==
    ADMIN_EMAIL.toLowerCase()
  ) {
    return json(
      {
        error:
          "Invalid email or password."
      },
      401,
      env
    );
  }

  if (
    !(await secureStringEqual(
      password,
      env.ADMIN_PASSWORD
    ))
  ) {
    return json(
      {
        error:
          "Invalid email or password."
      },
      401,
      env
    );
  }

  const token =
    crypto.randomUUID();

  const now = Date.now();
  const expires =
    now + SESSION_DURATION;

  await env.DB.prepare(`
    INSERT INTO sessions
    (
      token,
      created_at,
      expires_at
    )
    VALUES (?, ?, ?)
  `)
    .bind(
      token,
      now,
      expires
    )
    .run();

  return json(
    {
      success: true,
      token,
      expires_at: expires
    },
    200,
    env
  );
}


async function logout(request, env) {
  const session =
    await authenticate(request, env);

  if (!session) {
    return json(
      {
        error: "Unauthorized"
      },
      401,
      env
    );
  }

  await env.DB.prepare(`
    DELETE FROM sessions
    WHERE token = ?
  `)
    .bind(session.token)
    .run();

  return json(
    {
      success: true
    },
    200,
    env
  );
}


async function authenticate(request, env) {
  const authorization =
    request.headers.get("Authorization");

  if (
    !authorization ||
    !authorization.startsWith("Bearer ")
  ) {
    return null;
  }

  const token =
    authorization
      .slice(7)
      .trim();

  if (!token) {
    return null;
  }

  const session =
    await env.DB.prepare(`
      SELECT
        token,
        created_at,
        expires_at
      FROM sessions
      WHERE token = ?
      AND expires_at > ?
      LIMIT 1
    `)
      .bind(
        token,
        Date.now()
      )
      .first();

  return session || null;
}


/* =========================================================
   ADMIN API
========================================================= */

async function handleAdminAPI(
  request,
  env,
  url
) {

  /*
   * DASHBOARD
   */

  if (
    url.pathname ===
      "/api/admin/dashboard" &&
    request.method === "GET"
  ) {

    const members =
      await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM members
      `).first();

    const messages =
      await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM messages
      `).first();

    const unread =
      await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM messages
        WHERE is_read = 0
      `).first();

    const images =
      await env.DB.prepare(`
        SELECT COUNT(*) AS total
        FROM website_images
      `).first();

    return json(
      {
        members:
          Number(members?.total || 0),

        messages:
          Number(messages?.total || 0),

        unread:
          Number(unread?.total || 0),

        images:
          Number(images?.total || 0)
      },
      200,
      env
    );
  }


  /*
   * MESSAGES
   */

  if (
    url.pathname ===
      "/api/admin/messages" &&
    request.method === "GET"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          sender_name,
          sender_email,
          subject,
          message,
          is_read,
          created_at
        FROM messages
        ORDER BY created_at DESC
      `).all();

    return json(
      result.results || [],
      200,
      env
    );
  }


  /*
   * MARK MESSAGE READ
   */

  const readMatch =
    url.pathname.match(
      /^\/api\/admin\/messages\/(\d+)\/read$/
    );

  if (
    readMatch &&
    request.method === "POST"
  ) {

    const id =
      Number(readMatch[1]);

    await env.DB.prepare(`
      UPDATE messages
      SET is_read = 1
      WHERE id = ?
    `)
      .bind(id)
      .run();

    return json(
      {
        success: true
      },
      200,
      env
    );
  }


  /*
   * DELETE MESSAGE
   */

  const messageMatch =
    url.pathname.match(
      /^\/api\/admin\/messages\/(\d+)$/
    );

  if (
    messageMatch &&
    request.method === "DELETE"
  ) {

    const id =
      Number(messageMatch[1]);

    await env.DB.prepare(`
      DELETE FROM messages
      WHERE id = ?
    `)
      .bind(id)
      .run();

    return json(
      {
        success: true
      },
      200,
      env
    );
  }


  /*
   * MEMBERS - GET
   */

  if (
    url.pathname ===
      "/api/admin/members" &&
    request.method === "GET"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          name,
          role,
          photo,
          created_at
        FROM members
        ORDER BY created_at DESC
      `).all();

    return json(
      result.results || [],
      200,
      env
    );
  }


  /*
   * MEMBERS - CREATE
   */

  if (
    url.pathname ===
      "/api/admin/members" &&
    request.method === "POST"
  ) {

    const body =
      await request.json().catch(
        () => null
      );

    if (!body) {
      return json(
        {
          error:
            "Invalid request."
        },
        400,
        env
      );
    }

    const name =
      String(
        body.name || ""
      ).trim();

    const role =
      String(
        body.role || ""
      ).trim();

    const photo =
      String(
        body.photo || ""
      ).trim();

    if (!name) {
      return json(
        {
          error:
            "Member name is required."
        },
        400,
        env
      );
    }

    await env.DB.prepare(`
      INSERT INTO members
      (
        name,
        role,
        photo,
        created_at
      )
      VALUES (?, ?, ?, ?)
    `)
      .bind(
        name,
        role,
        photo,
        Date.now()
      )
      .run();

    return json(
      {
        success: true
      },
      200,
      env
    );
  }


  /*
   * MEMBERS - UPDATE
   */

  const memberMatch =
    url.pathname.match(
      /^\/api\/admin\/members\/(\d+)$/
    );

  if (
    memberMatch &&
    request.method === "PUT"
  ) {

    const id =
      Number(memberMatch[1]);

    const body =
      await request.json().catch(
        () => null
      );

    if (!body) {
      return json(
        {
          error:
            "Invalid request."
        },
        400,
        env
      );
    }

    const name =
      String(
        body.name || ""
      ).trim();

    const role =
      String(
        body.role || ""
      ).trim();

    const photo =
      String(
        body.photo || ""
      ).trim();

    if (!name) {
      return json(
        {
          error:
            "Member name is required."
        },
        400,
        env
      );
    }

    await env.DB.prepare(`
      UPDATE members
      SET
        name = ?,
        role = ?,
        photo = ?
      WHERE id = ?
    `)
      .bind(
        name,
        role,
        photo,
        id
      )
      .run();

    return json(
      {
        success: true
      },
      200,
      env
    );
  }


  /*
   * MEMBERS - DELETE
   */

  if (
    memberMatch &&
    request.method === "DELETE"
  ) {

    const id =
      Number(memberMatch[1]);

    await env.DB.prepare(`
      DELETE FROM members
      WHERE id = ?
    `)
      .bind(id)
      .run();

    return json(
      {
        success: true
      },
      200,
      env
    );
  }


  /*
   * WEBSITE IMAGES - LIST
   */

  if (
    url.pathname ===
      "/api/admin/images" &&
    request.method === "GET"
  ) {

    const result =
      await env.DB.prepare(`
        SELECT
          id,
          title,
          description,
          r2_key,
          original_name,
          content_type,
          size,
          created_at,
          updated_at
        FROM website_images
        ORDER BY created_at DESC
      `).all();

    return json(
      result.results || [],
      200,
      env
    );
  }


  /*
   * WEBSITE IMAGES - UPLOAD
   */

  if (
    url.pathname ===
      "/api/admin/images" &&
    request.method === "POST"
  ) {

    return uploadWebsiteImage(
      request,
      env
    );
  }


  /*
   * WEBSITE IMAGE - UPDATE METADATA
   */

  const imageMatch =
    url.pathname.match(
      /^\/api\/admin\/images\/([^/]+)$/
    );

  if (
    imageMatch &&
    request.method === "PUT"
  ) {

    const id =
      decodeURIComponent(
        imageMatch[1]
      );

    return updateWebsiteImage(
      request,
      env,
      id
    );
  }


  /*
   * WEBSITE IMAGE - REPLACE FILE
   */

  const replaceMatch =
    url.pathname.match(
      /^\/api\/admin\/images\/([^/]+)\/replace$/
    );

  if (
    replaceMatch &&
    request.method === "POST"
  ) {

    const id =
      decodeURIComponent(
        replaceMatch[1]
      );

    return replaceWebsiteImage(
      request,
      env,
      id
    );
  }


  /*
   * WEBSITE IMAGE - DELETE
   */

  if (
    imageMatch &&
    request.method === "DELETE"
  ) {

    const id =
      decodeURIComponent(
        imageMatch[1]
      );

    return deleteWebsiteImage(
      env,
      id
    );
  }


  return json(
    {
      error:
        "Admin endpoint not found."
    },
    404,
    env
  );
}


/* =========================================================
   WEBSITE IMAGE MANAGEMENT
========================================================= */

async function uploadWebsiteImage(
  request,
  env
) {

  const form =
    await request.formData();

  const file =
    form.get("file");

  const title =
    String(
      form.get("title") || ""
    ).trim();

  const description =
    String(
      form.get("description") || ""
    ).trim();


  if (!(file instanceof File)) {
    return json(
      {
        error:
          "Please select an image."
      },
      400,
      env
    );
  }


  const validation =
    validateImage(file);

  if (validation) {
    return json(
      {
        error: validation
      },
      400,
      env
    );
  }


  const id =
    crypto.randomUUID();

  const extension =
    getExtension(file.type);

  const key =
    `${R2_PREFIX}${id}.${extension}`;


  await env.MEDIA.put(
    key,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          file.type,

        cacheControl:
          "public, max-age=31536000"
      },

      customMetadata: {
        originalName:
          file.name
      }
    }
  );


  await env.DB.prepare(`
    INSERT INTO website_images
    (
      id,
      title,
      description,
      r2_key,
      original_name,
      content_type,
      size,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)
    .bind(
      id,
      title,
      description,
      key,
      file.name,
      file.type,
      file.size,
      Date.now(),
      Date.now()
    )
    .run();


  return json(
    {
      success: true,
      id,
      image_url:
        `/api/images/${encodeURIComponent(id)}`
    },
    201,
    env
  );
}


/*
 * Replace an existing managed image.
 */
async function replaceWebsiteImage(
  request,
  env,
  id
) {

  const existing =
    await env.DB.prepare(`
      SELECT
        id,
        r2_key
      FROM website_images
      WHERE id = ?
      LIMIT 1
    `)
      .bind(id)
      .first();


  if (!existing) {
    return json(
      {
        error:
          "Managed image not found."
      },
      404,
      env
    );
  }


  const form =
    await request.formData();

  const file =
    form.get("file");


  if (!(file instanceof File)) {
    return json(
      {
        error:
          "Please select a replacement image."
      },
      400,
      env
    );
  }


  const validation =
    validateImage(file);

  if (validation) {
    return json(
      {
        error: validation
      },
      400,
      env
    );
  }


  const extension =
    getExtension(file.type);

  const newKey =
    `${R2_PREFIX}${crypto.randomUUID()}.${extension}`;


  await env.MEDIA.put(
    newKey,
    file.stream(),
    {
      httpMetadata: {
        contentType:
          file.type,

        cacheControl:
          "public, max-age=31536000"
      },

      customMetadata: {
        originalName:
          file.name
      }
    }
  );


  /*
   * Delete the previous R2 object
   * only after the new one has been
   * successfully uploaded.
   */
  await env.MEDIA.delete(
    existing.r2_key
  );


  await env.DB.prepare(`
    UPDATE website_images
    SET
      r2_key = ?,
      original_name = ?,
      content_type = ?,
      size = ?,
      updated_at = ?
    WHERE id = ?
  `)
    .bind(
      newKey,
      file.name,
      file.type,
      file.size,
      Date.now(),
      id
    )
    .run();


  return json(
    {
      success: true,
      id,
      image_url:
        `/api/images/${encodeURIComponent(id)}`
    },
    200,
    env
  );
}


/*
 * Edit image information.
 *
 * This changes metadata such as title
 * and description.
 *
 * Actual visual editing/cropping would
 * require a separate image-processing
 * layer and is intentionally not assumed
 * here.
 */
async function updateWebsiteImage(
  request,
  env,
  id
) {

  const body =
    await request.json().catch(
      () => null
    );


  if (!body) {
    return json(
      {
        error:
          "Invalid request."
      },
      400,
      env
    );
  }


  const title =
    String(
      body.title || ""
    ).trim();

  const description =
    String(
      body.description || ""
    ).trim();


  const result =
    await env.DB.prepare(`
      UPDATE website_images
      SET
        title = ?,
        description = ?,
        updated_at = ?
      WHERE id = ?
    `)
      .bind(
        title,
        description,
        Date.now(),
        id
      )
      .run();


  if (!result.meta?.changes) {
    return json(
      {
        error:
          "Managed image not found."
      },
      404,
      env
    );
  }


  return json(
    {
      success: true
    },
    200,
    env
  );
}


/*
 * Delete managed website image.
 */
async function deleteWebsiteImage(
  env,
  id
) {

  const image =
    await env.DB.prepare(`
      SELECT
        r2_key
      FROM website_images
      WHERE id = ?
      LIMIT 1
    `)
      .bind(id)
      .first();


  if (!image) {
    return json(
      {
        error:
          "Managed image not found."
      },
      404,
      env
    );
  }


  await env.MEDIA.delete(
    image.r2_key
  );


  await env.DB.prepare(`
    DELETE FROM website_images
    WHERE id = ?
  `)
    .bind(id)
    .run();


  return json(
    {
      success: true
    },
    200,
    env
  );
}


/* =========================================================
   PUBLIC IMAGE
========================================================= */

async function serveImage(
  request,
  env,
  url
) {

  if (
    request.method !== "GET" &&
    request.method !== "HEAD"
  ) {
    return json(
      {
        error:
          "Method not allowed."
      },
      405,
      env
    );
  }


  const id =
    decodeURIComponent(
      url.pathname
        .replace(
          "/api/images/",
          ""
        )
    );


  if (!id) {
    return new Response(
      "Image not found.",
      {
        status: 404
      }
    );
  }


  const image =
    await env.DB.prepare(`
      SELECT
        r2_key,
        content_type
      FROM website_images
      WHERE id = ?
      LIMIT 1
    `)
      .bind(id)
      .first();


  if (!image) {
    return new Response(
      "Image not found.",
      {
        status: 404
      }
    );
  }


  const object =
    await env.MEDIA.get(
      image.r2_key
    );


  if (!object) {
    return new Response(
      "Image not found.",
      {
        status: 404
      }
    );
  }


  const headers =
    new Headers();

  headers.set(
    "Content-Type",
    image.content_type
  );

  headers.set(
    "Cache-Control",
    "public, max-age=31536000"
  );


  if (object.httpEtag) {
    headers.set(
      "ETag",
      object.httpEtag
    );
  }


  if (request.method === "HEAD") {
    return new Response(
      null,
      {
        status: 200,
        headers
      }
    );
  }


  return new Response(
    object.body,
    {
      status: 200,
      headers
    }
  );
}


/* =========================================================
   PUBLIC MEMBERS
========================================================= */

async function getPublicMembers(env) {

  const result =
    await env.DB.prepare(`
      SELECT
        id,
        name,
        role,
        photo
      FROM members
      ORDER BY created_at ASC
    `).all();


  return json(
    result.results || [],
    200,
    env
  );
}


/* =========================================================
   CONTACT MESSAGES
========================================================= */

async function createMessage(
  request,
  env
) {

  const body =
    await request.json().catch(
      () => null
    );


  if (!body) {
    return json(
      {
        error:
          "Invalid request."
      },
      400,
      env
    );
  }


  const name =
    String(
      body.name || ""
    ).trim();

  const email =
    String(
      body.email || ""
    ).trim();

  const subject =
    String(
      body.subject || ""
    ).trim();

  const message =
    String(
      body.message || ""
    ).trim();


  if (
    !name ||
    !email ||
    !message
  ) {
    return json(
      {
        error:
          "Name, email and message are required."
      },
      400,
      env
    );
  }


  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(email)
  ) {
    return json(
      {
        error:
          "Please enter a valid email address."
      },
      400,
      env
    );
  }


  if (
    name.length > 150 ||
    email.length > 254 ||
    subject.length > 200 ||
    message.length > 10000
  ) {
    return json(
      {
        error:
          "One or more fields are too long."
      },
      400,
      env
    );
  }


  await env.DB.prepare(`
    INSERT INTO messages
    (
      sender_name,
      sender_email,
      subject,
      message,
      is_read,
      created_at
    )
    VALUES (?, ?, ?, ?, 0, ?)
  `)
    .bind(
      name,
      email,
      subject,
      message,
      Date.now()
    )
    .run();


  return json(
    {
      success: true,
      message:
        "Your message has been received."
    },
    201,
    env
  );
}


/* =========================================================
   HELPERS
========================================================= */

function validateImage(file) {

  if (
    file.size >
    MAX_IMAGE_SIZE
  ) {
    return "Image is too large. Maximum size is 5MB.";
  }


  if (
    !ALLOWED_IMAGE_TYPES.includes(
      file.type
    )
  ) {
    return "Only JPG, PNG and WebP images are allowed.";
  }


  return null;
}


function getExtension(type) {

  if (type === "image/png") {
    return "png";
  }

  if (type === "image/webp") {
    return "webp";
  }

  return "jpg";
}


/*
 * Hash both strings with SHA-256 before
 * comparing their bytes.
 *
 * The original password is still kept
 * only as a Cloudflare Secret.
 */
async function secureStringEqual(
  a,
  b
) {

  const encoder =
    new TextEncoder();

  const aHash =
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(a)
      )
    );

  const bHash =
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(b)
      )
    );


  if (
    aHash.length !==
    bHash.length
  ) {
    return false;
  }


  let difference = 0;

  for (
    let i = 0;
    i < aHash.length;
    i++
  ) {
    difference |=
      aHash[i] ^
      bHash[i];
  }


  return difference === 0;
}


function corsHeaders(env) {

  /*
   * Set ALLOWED_ORIGIN as a Worker variable.
   *
   * Example:
   * https://mastercrosscharityfoundation.com
   */
  const origin =
    env.ALLOWED_ORIGIN ||
    "https://mastercrosscharityfoundation.com";


  return {
    "Access-Control-Allow-Origin":
      origin,

    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",

    "Access-Control-Allow-Methods":
      "GET, POST, PUT, DELETE, OPTIONS",

    "Access-Control-Max-Age":
      "86400"
  };
}


function json(
  data,
  status = 200,
  env
) {

  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",

        ...corsHeaders(env)
      }
    }
  );
}


/* =========================================================
   ADMIN HTML
========================================================= */

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1.0">

<title>MasterCross Charity Foundation — Admin</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family:
    Arial,
    Helvetica,
    sans-serif;

  background:
    #f7f8f4;

  color:
    #183b2a;
}

button,
input,
textarea {
  font: inherit;
}

button {
  cursor: pointer;
}

.hidden {
  display: none !important;
}


/* LOGIN */

#loginScreen {
  min-height: 100vh;

  display: flex;
  align-items: center;
  justify-content: center;

  padding: 20px;

  background:
    linear-gradient(
      135deg,
      #ffffff,
      #fff8df
    );
}

.login-box {
  width: 100%;
  max-width: 430px;

  background: white;

  padding: 35px;

  border-radius: 20px;

  box-shadow:
    0 15px 50px
    rgba(0,0,0,.10);
}

.login-box h1 {
  margin-top: 0;
  font-size: 28px;
}

.login-box p {
  color: #68756d;
}

input,
textarea {
  width: 100%;

  padding: 13px 14px;

  border: 1px solid #dce3dd;

  border-radius: 10px;

  outline: none;

  background: #fff;
}

input:focus,
textarea:focus {
  border-color: #168c54;
}

label {
  display: block;

  margin:
    16px 0 7px;

  font-weight: 700;
}

.primary {
  width: 100%;

  margin-top: 20px;

  padding: 13px 18px;

  border: 0;

  border-radius: 10px;

  background:
    #168c54;

  color: white;

  font-weight: 700;
}


/* ADMIN */

#adminScreen {
  min-height: 100vh;

  display: grid;

  grid-template-columns:
    240px 1fr;
}

.sidebar {
  background:
    #183b2a;

  color: white;

  padding: 25px 18px;
}

.brand {
  font-weight: 800;

  font-size: 18px;

  margin-bottom: 30px;
}

.nav button {
  display: block;

  width: 100%;

  border: 0;

  background: transparent;

  color: white;

  text-align: left;

  padding: 13px;

  margin-bottom: 5px;

  border-radius: 9px;
}

.nav button:hover {
  background:
    rgba(255,255,255,.10);
}

.logout {
  margin-top: 30px !important;

  background:
    #d95b35 !important;
}

.content {
  padding: 30px;

  overflow-x: auto;
}

.topbar {
  display: flex;

  justify-content:
    space-between;

  align-items: center;

  margin-bottom: 25px;
}

.topbar h1 {
  margin: 0;
}

.cards {
  display: grid;

  grid-template-columns:
    repeat(
      auto-fit,
      minmax(180px,1fr)
    );

  gap: 18px;

  margin-bottom: 25px;
}

.card {
  background: white;

  padding: 22px;

  border-radius: 15px;

  box-shadow:
    0 5px 20px
    rgba(0,0,0,.05);
}

.card strong {
  display: block;

  font-size: 30px;

  margin-top: 8px;
}

.panel {
  background: white;

  padding: 22px;

  border-radius: 15px;

  box-shadow:
    0 5px 20px
    rgba(0,0,0,.05);

  margin-bottom: 20px;
}

.panel h2 {
  margin-top: 0;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;

  border-collapse:
    collapse;
}

th,
td {
  text-align: left;

  padding: 12px;

  border-bottom:
    1px solid #edf0ed;
}

th {
  color:
    #536259;
}

.action {
  border: 0;

  border-radius: 7px;

  padding: 8px 11px;

  margin: 2px;
}

.edit {
  background:
    #f2c94c;
}

.delete {
  background:
    #d95b35;

  color: white;
}

.read {
  background:
    #168c54;

  color: white;
}

.image-grid {
  display: grid;

  grid-template-columns:
    repeat(
      auto-fit,
      minmax(220px,1fr)
    );

  gap: 18px;
}

.image-card {
  border:
    1px solid #e4e9e4;

  border-radius: 14px;

  overflow: hidden;

  background: white;
}

.image-card img {
  width: 100%;

  height: 170px;

  object-fit: cover;

  display: block;
}

.image-card-body {
  padding: 15px;
}

.upload-box {
  border:
    2px dashed #b9c7bd;

  padding: 25px;

  border-radius: 14px;

  text-align: center;

  margin-bottom: 25px;
}

.small {
  font-size: 13px;

  color: #6d786f;
}

.message {
  border-bottom:
    1px solid #e8ece8;

  padding: 16px 0;
}

.message:last-child {
  border-bottom: 0;
}

.badge {
  display: inline-block;

  padding: 4px 8px;

  border-radius: 20px;

  font-size: 11px;

  background:
    #f2c94c;
}

@media(max-width:760px) {

  #adminScreen {
    grid-template-columns: 1fr;
  }

  .sidebar {
    position: static;
  }

  .content {
    padding: 18px;
  }

}

</style>
</head>

<body>

<div id="loginScreen">

  <div class="login-box">

    <h1>MasterCross Charity Foundation</h1>

    <p>
      Administration Portal
    </p>

    <form id="loginForm">

      <label>
        Email
      </label>

      <input
        id="loginEmail"
        type="email"
        autocomplete="username"
        required
      >

      <label>
        Password
      </label>

      <input
        id="loginPassword"
        type="password"
        autocomplete="current-password"
        required
      >

      <button
        class="primary"
        type="submit"
      >
        Sign In
      </button>

    </form>

    <p id="loginError"></p>

  </div>

</div>


<div
  id="adminScreen"
  class="hidden"
>

  <aside class="sidebar">

    <div class="brand">
      MasterCross Charity Foundation
    </div>

    <div class="nav">

      <button
        onclick="showSection('dashboard')"
      >
        Dashboard
      </button>

      <button
        onclick="showSection('messages')"
      >
        Messages
      </button>

      <button
        onclick="showSection('members')"
      >
        Members
      </button>

      <button
        onclick="showSection('images')"
      >
        Website Images
      </button>

      <button
        class="logout"
        onclick="logout()"
      >
        Logout
      </button>

    </div>

  </aside>


  <main class="content">

    <div class="topbar">

      <h1 id="sectionTitle">
        Dashboard
      </h1>

    </div>


    <!-- DASHBOARD -->

    <section id="dashboard">

      <div class="cards">

        <div class="card">
          Members
          <strong id="memberCount">
            0
          </strong>
        </div>

        <div class="card">
          Messages
          <strong id="messageCount">
            0
          </strong>
        </div>

        <div class="card">
          Unread
          <strong id="unreadCount">
            0
          </strong>
        </div>

        <div class="card">
          Website Images
          <strong id="imageCount">
            0
          </strong>
        </div>

      </div>

      <div class="panel">

        <h2>
          Administration
        </h2>

        <p>
          Manage membership records,
          contact messages and website
          images from this dashboard.
        </p>

      </div>

    </section>


    <!-- MESSAGES -->

    <section
      id="messages"
      class="hidden"
    >

      <div class="panel">

        <h2>
          Contact Messages
        </h2>

        <div id="messagesList">
          Loading...
        </div>

      </div>

    </section>


    <!-- MEMBERS -->

    <section
      id="members"
      class="hidden"
    >

      <div class="panel">

        <h2>
          Add Member
        </h2>

        <form id="memberForm">

          <label>
            Name
          </label>

          <input
            id="memberName"
            required
          >

          <label>
            Role
          </label>

          <input
            id="memberRole"
          >

          <label>
            Photo URL
          </label>

          <input
            id="memberPhoto"
          >

          <button
            class="primary"
            type="submit"
          >
            Add Member
          </button>

        </form>

      </div>


      <div class="panel">

        <h2>
          Membership List
        </h2>

        <div
          class="table-wrap"
        >

          <table>

            <thead>

              <tr>
                <th>Name</th>
                <th>Role</th>
                <th>Photo</th>
                <th>Action</th>
              </tr>

            </thead>

            <tbody
              id="membersTable"
            ></tbody>

          </table>

        </div>

      </div>

    </section>


    <!-- IMAGES -->

    <section
      id="images"
      class="hidden"
    >

      <div class="panel">

        <h2>
          Website Images
        </h2>

        <p>
          Upload additional images or
          manage images that have been
          migrated into the website image
          management system.
        </p>

        <div class="upload-box">

          <form
            id="imageForm"
          >

            <input
              id="imageFile"
              type="file"
              accept="image/jpeg,image/png,image/webp"
              required
            >

            <label>
              Image title
            </label>

            <input
              id="imageTitle"
              placeholder="Image title"
            >

            <label>
              Description
            </label>

            <textarea
              id="imageDescription"
              placeholder="Optional description"
            ></textarea>

            <button
              class="primary"
              type="submit"
            >
              Upload Image
            </button>

          </form>

          <p class="small">
            JPG, PNG and WebP. Maximum 5MB.
          </p>

        </div>

        <div
          id="imageGrid"
          class="image-grid"
        ></div>

      </div>

    </section>

  </main>

</div>


<script>

let token =
  localStorage.getItem(
    "mcf_admin_token"
  );


const loginScreen =
  document.getElementById(
    "loginScreen"
  );

const adminScreen =
  document.getElementById(
    "adminScreen"
  );


function api(
  path,
  options = {}
) {

  options.headers =
    options.headers || {};

  options.headers.Authorization =
    "Bearer " + token;

  return fetch(
    path,
    options
  );
}


function showAdmin() {

  loginScreen.classList
    .add("hidden");

  adminScreen.classList
    .remove("hidden");

  loadDashboard();
}


function showLogin() {

  adminScreen.classList
    .add("hidden");

  loginScreen.classList
    .remove("hidden");
}


async function login(event) {

  event.preventDefault();

  const email =
    document.getElementById(
      "loginEmail"
    ).value;

  const password =
    document.getElementById(
      "loginPassword"
    ).value;

  const response =
    await fetch(
      "/api/login",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          email,
          password
        })
      }
    );

  const data =
    await response.json();

  if (!response.ok) {

    document.getElementById(
      "loginError"
    ).textContent =
      data.error ||
      "Login failed.";

    return;
  }

  token =
    data.token;

  localStorage.setItem(
    "mcf_admin_token",
    token
  );

  showAdmin();
}


async function logout() {

  if (token) {

    await api(
      "/api/logout",
      {
        method: "POST"
      }
    ).catch(
      () => {}
    );
  }

  localStorage.removeItem(
    "mcf_admin_token"
  );

  token = null;

  showLogin();
}


function showSection(
  section
) {

  const sections = [
    "dashboard",
    "messages",
    "members",
    "images"
  ];

  sections.forEach(
    id => {

      document
        .getElementById(id)
        .classList
        .add("hidden");

    }
  );

  document
    .getElementById(section)
    .classList
    .remove("hidden");


  const titles = {
    dashboard:
      "Dashboard",

    messages:
      "Messages",

    members:
      "Members",

    images:
      "Website Images"
  };


  document.getElementById(
    "sectionTitle"
  ).textContent =
    titles[section];


  if (section === "dashboard") {
    loadDashboard();
  }

  if (section === "messages") {
    loadMessages();
  }

  if (section === "members") {
    loadMembers();
  }

  if (section === "images") {
    loadImages();
  }
}


/* DASHBOARD */

async function loadDashboard() {

  const response =
    await api(
      "/api/admin/dashboard"
    );

  if (response.status === 401) {
    logout();
    return;
  }

  const data =
    await response.json();

  document.getElementById(
    "memberCount"
  ).textContent =
    data.members;

  document.getElementById(
    "messageCount"
  ).textContent =
    data.messages;

  document.getElementById(
    "unreadCount"
  ).textContent =
    data.unread;

  document.getElementById(
    "imageCount"
  ).textContent =
    data.images;
}


/* MESSAGES */

async function loadMessages() {

  const response =
    await api(
      "/api/admin/messages"
    );

  if (response.status === 401) {
    logout();
    return;
  }

  const messages =
    await response.json();

  const box =
    document.getElementById(
      "messagesList"
    );

  if (!messages.length) {

    box.innerHTML =
      "<p>No messages yet.</p>";

    return;
  }


  box.innerHTML =
    messages.map(
      message => `

        <div class="message">

          <strong>
            ${escapeHTML(
              message.sender_name
            )}
          </strong>

          ${
            message.is_read
              ? ""
              : '<span class="badge">Unread</span>'
          }

          <div class="small">
            ${escapeHTML(
              message.sender_email
            )}
          </div>

          <h3>
            ${escapeHTML(
              message.subject ||
              "No subject"
            )}
          </h3>

          <p>
            ${escapeHTML(
              message.message
            )}
          </p>

          <button
            class="action read"
            onclick="markRead(${message.id})"
          >
            Mark Read
          </button>

          <button
            class="action delete"
            onclick="deleteMessage(${message.id})"
          >
            Delete
          </button>

        </div>

      `
    ).join("");
}


async function markRead(id) {

  await api(
    "/api/admin/messages/" +
    id +
    "/read",
    {
      method: "POST"
    }
  );

  loadMessages();
}


async function deleteMessage(id) {

  if (
    !confirm(
      "Delete this message?"
    )
  ) {
    return;
  }

  await api(
    "/api/admin/messages/" +
    id,
    {
      method: "DELETE"
    }
  );

  loadMessages();
}


/* MEMBERS */

async function loadMembers() {

  const response =
    await api(
      "/api/admin/members"
    );

  if (response.status === 401) {
    logout();
    return;
  }

  const members =
    await response.json();

  const table =
    document.getElementById(
      "membersTable"
    );


  table.innerHTML =
    members.map(
      member => `

        <tr>

          <td>
            ${escapeHTML(
              member.name
            )}
          </td>

          <td>
            ${escapeHTML(
              member.role || ""
            )}
          </td>

          <td>
            ${member.photo
              ? "Available"
              : "—"}
          </td>

          <td>

            <button
              class="action edit"
              onclick="editMember(${member.id})"
            >
              Edit
            </button>

            <button
              class="action delete"
              onclick="deleteMember(${member.id})"
            >
              Delete
            </button>

          </td>

        </tr>

      `
    ).join("");
}


async function addMember(event) {

  event.preventDefault();

  const name =
    document.getElementById(
      "memberName"
    ).value.trim();

  const role =
    document.getElementById(
      "memberRole"
    ).value.trim();

  const photo =
    document.getElementById(
      "memberPhoto"
    ).value.trim();


  await api(
    "/api/admin/members",
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/json",

        "Authorization":
          "Bearer " + token
      },

      body: JSON.stringify({
        name,
        role,
        photo
      })
    }
  );


  event.target.reset();

  loadMembers();
  loadDashboard();
}


async function editMember(id) {

  const name =
    prompt(
      "Member name:"
    );

  if (name === null) {
    return;
  }

  const role =
    prompt(
      "Member role:"
    ) || "";

  const photo =
    prompt(
      "Member photo URL:"
    ) || "";


  await api(
    "/api/admin/members/" +
    id,
    {
      method: "PUT",

      headers: {
        "Content-Type":
          "application/json",

        "Authorization":
          "Bearer " + token
      },

      body: JSON.stringify({
        name,
        role,
        photo
      })
    }
  );


  loadMembers();
}


async function deleteMember(id) {

  if (
    !confirm(
      "Delete this member?"
    )
  ) {
    return;
  }


  await api(
    "/api/admin/members/" +
    id,
    {
      method: "DELETE"
    }
  );


  loadMembers();
  loadDashboard();
}


/* IMAGES */

async function loadImages() {

  const response =
    await api(
      "/api/admin/images"
    );

  if (response.status === 401) {
    logout();
    return;
  }

  const images =
    await response.json();

  const grid =
    document.getElementById(
      "imageGrid"
    );


  if (!images.length) {

    grid.innerHTML =
      "<p>No managed website images yet.</p>";

    return;
  }


  grid.innerHTML =
    images.map(
      image => `

        <div class="image-card">

          <img
            src="/api/images/${encodeURIComponent(
              image.id
            )}"
            alt="${escapeHTML(
              image.title || ""
            )}"
          >

          <div class="image-card-body">

            <strong>
              ${escapeHTML(
                image.title ||
                "Untitled"
              )}
            </strong>

            <p>
              ${escapeHTML(
                image.description ||
                ""
              )}
            </p>

            <button
              class="action edit"
              onclick="editImage('${escapeJS(
                image.id
              )}')"
            >
              Edit
            </button>

            <button
              class="action edit"
              onclick="replaceImage('${escapeJS(
                image.id
              )}')"
            >
              Replace
            </button>

            <button
              class="action delete"
              onclick="deleteImage('${escapeJS(
                image.id
              )}')"
            >
              Delete
            </button>

          </div>

        </div>

      `
    ).join("");
}


async function uploadImage(event) {

  event.preventDefault();

  const file =
    document.getElementById(
      "imageFile"
    ).files[0];

  if (!file) {
    alert(
      "Please select an image."
    );

    return;
  }


  const form =
    new FormData();

  form.append(
    "file",
    file
  );

  form.append(
    "title",
    document.getElementById(
      "imageTitle"
    ).value
  );

  form.append(
    "description",
    document.getElementById(
      "imageDescription"
    ).value
  );


  await api(
    "/api/admin/images",
    {
      method: "POST",
      body: form
    }
  );


  event.target.reset();

  loadImages();
  loadDashboard();
}


async function editImage(id) {

  const title =
    prompt(
      "New image title:"
    );

  if (title === null) {
    return;
  }

  const description =
    prompt(
      "New image description:"
    ) || "";


  await api(
    "/api/admin/images/" +
    encodeURIComponent(id),
    {
      method: "PUT",

      headers: {
        "Content-Type":
          "application/json"
      },

      body: JSON.stringify({
        title,
        description
      })
    }
  );


  loadImages();
}


async function replaceImage(id) {

  const input =
    document.createElement(
      "input"
    );

  input.type = "file";

  input.accept =
    "image/jpeg,image/png,image/webp";


  input.onchange =
    async () => {

      if (!input.files[0]) {
        return;
      }


      const form =
        new FormData();

      form.append(
        "file",
        input.files[0]
      );


      await api(
        "/api/admin/images/" +
        encodeURIComponent(id) +
        "/replace",
        {
          method: "POST",
          body: form
        }
      );


      loadImages();
    };


  input.click();
}


async function deleteImage(id) {

  if (
    !confirm(
      "Delete this managed website image?"
    )
  ) {
    return;
  }


  await api(
    "/api/admin/images/" +
    encodeURIComponent(id),
    {
      method: "DELETE"
    }
  );


  loadImages();
  loadDashboard();
}


function escapeHTML(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


function escapeJS(value) {

  return String(value)
    .replaceAll("\\\\", "\\\\\\\\")
    .replaceAll("'", "\\'");
}


/* EVENTS */

document
  .getElementById("loginForm")
  .addEventListener(
    "submit",
    login
  );


document
  .getElementById("memberForm")
  .addEventListener(
    "submit",
    addMember
  );


document
  .getElementById("imageForm")
  .addEventListener(
    "submit",
    uploadImage
  );


/* START */

if (token) {
  showAdmin();
} else {
  showLogin();
}

</script>

</body>
</html>`;
