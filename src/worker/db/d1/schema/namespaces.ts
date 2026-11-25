import { integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

import { users } from "./users";

// A namespace owns repositories and is addressed in URLs as `/:owner` (the
// `:owner` segment equals `slug`). It is created when a signed-in user
// confirms the suggested name (from `preferred_username` or the email
// local-part), race-protected against concurrent claims via
// `ON CONFLICT DO NOTHING`.
export const namespaces = sqliteTable("namespaces", {
  id: text("id").primaryKey(),
  slug: text("slug").notNull().unique(),
  createdBy: text("created_by")
    .notNull()
    .references(() => users.id, { onDelete: "restrict" }),
  createdAt: integer("created_at").notNull(),
});

export type NamespaceRow = typeof namespaces.$inferSelect;
export type NewNamespaceRow = typeof namespaces.$inferInsert;
