import { createClient } from "redis";

const client = createClient();

client
  .connect()
  .then(() => {
    console.log("client connected to db.");
  })
  .catch((err) => {
    console.log(err);
  });
// client.on("connect", () => {
//   console.log("client connected to db.");
// });

client.on("ready", () => {
  console.log("clint connected and ready to use.");
});

// client.on("error", (error) => {
//   console.log(error);
// });

client.on("end", () => {
  console.log("client disconnected.");
});

process.on("SIGINT", () => {
  client.quit();
});

export default client;
