import { Queue } from 'bullmq';

const connection = { url: process.env.REDIS_URL };

export const queues = {
  notifications: new Queue('notifications', { connection }),
  pdfJobs:       new Queue('pdf_jobs', { connection }),
};
