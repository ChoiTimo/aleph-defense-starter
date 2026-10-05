import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
    if (request.method !== 'GET') {
        response.setHeader('Allow', 'GET');
        return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl || !supabaseSecretKey) {
        return response.status(500).json({ error: 'SERVER_CONFIG_ERROR' });
    }

    const supabase = createClient(supabaseUrl, supabaseSecretKey, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
        },
    });

    const { data, error } = await supabase
        .from('virtual_notes')
        .select('title, content')
        .order('id', { ascending: true });

    if (error) {
        return response.status(500).json({ error: 'NOTES_READ_FAILED' });
    }

    return response.status(200).json({ notes: data });
}
