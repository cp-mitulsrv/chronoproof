import nodemailer, { type Transporter } from "nodemailer";
import config from "../config/index.js";

// Lazily-created singleton transporter (SMTP connection pool).
let transporter: Transporter | null = null;

/** True when SMTP is configured (host + credentials present). */
export function emailConfigured(): boolean {
  return Boolean(config.smtp.host && config.smtp.user && config.smtp.password);
}

function getTransporter(): Transporter {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure, // false for 587 (STARTTLS), true for 465
      auth: { user: config.smtp.user, pass: config.smtp.password },
    });
  }
  return transporter;
}

export interface InvitationEmailParams {
  to: string;
  role: string;
  acceptUrl: string;
  workspaceName?: string;
  inviterName?: string;
}

/**
 * Send a workspace invitation email. Best-effort: returns false (never throws)
 * if SMTP is unconfigured or delivery fails, so the invite API still succeeds.
 */
export async function sendInvitationEmail(p: InvitationEmailParams): Promise<boolean> {
  if (!emailConfigured()) return false;

  const workspace = p.workspaceName ? `the "${p.workspaceName}" workspace` : "a ChronoProof workspace";
  const inviter = p.inviterName ? `${p.inviterName} invited you` : "You've been invited";
  const subject = `You're invited to ${p.workspaceName ?? "ChronoProof"}`;

  const text =
    `${inviter} to join ${workspace} on ChronoProof as ${p.role}.\n\n` +
    `Accept your invitation:\n${p.acceptUrl}\n\n` +
    `This link expires in 7 days. If you weren't expecting this, you can ignore it.`;

  const html =
    `<div style="font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:auto">` +
    `<h2 style="margin:0 0 12px">You're invited to ChronoProof</h2>` +
    `<p>${inviter} to join <strong>${workspace}</strong> as <strong>${p.role}</strong>.</p>` +
    `<p style="margin:24px 0">` +
    `<a href="${p.acceptUrl}" style="background:#2563eb;color:#fff;padding:12px 20px;` +
    `border-radius:6px;text-decoration:none;display:inline-block">Accept invitation</a>` +
    `</p>` +
    `<p style="color:#666;font-size:13px">Or paste this link into your browser:<br>` +
    `<a href="${p.acceptUrl}">${p.acceptUrl}</a></p>` +
    `<p style="color:#999;font-size:12px">This link expires in 7 days. ` +
    `If you weren't expecting this, you can safely ignore this email.</p>` +
    `</div>`;

  try {
    await getTransporter().sendMail({ from: config.smtp.from, to: p.to, subject, text, html });
    return true;
  } catch (err) {
    console.error("[email] invitation send failed:", err instanceof Error ? err.message : err);
    return false;
  }
}
