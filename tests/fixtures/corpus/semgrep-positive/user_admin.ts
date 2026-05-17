// Corpus fixture — TRUE POSITIVE.
// A user-record deletion via an ORM, with no audit-log write and no DSR handler.
// Expected to trigger: missing-audit-javascript, missing-dsr-javascript.

export async function removeUser(id: string) {
  await prisma.user.delete({ where: { id } });
}
