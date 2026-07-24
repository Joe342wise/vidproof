import express from "express";

const app = express();
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "vidproof-backend" });
});

app.post("/evidence/register", (_req, res) => {
  res.status(501).json({ ok: false, error: "Fabric evidence registration is not implemented yet" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`backend listening on ${port}`);
});
