import { prisma } from '@/lib/prisma';


export async function POST(req: Request) {

    if (req.method !== 'POST') {
        return new Response(JSON.stringify({ error: 'Method not allowed!' }), {
            status: 405,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
    
    const newLog = await req.json();

    if (!newLog) {
        new Response(JSON.stringify({ error: 'Log not supplied!' }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }

    await prisma.serverLog.create({
        data: {
            ...newLog,
        },
    });

    return new Response(JSON.stringify({ success: 'log added' }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json'
        }
    });
}