#include "key_presence.h"
#ifdef _WIN32
#define API __declspec(dllexport)
#else
#define API
#endif
static key_presence state;
API void presence_reset(void) { key_presence_reset(&state); }
API int presence_begin(uint32_t cid, uint32_t epoch, int pressed, uint32_t now) {
    return key_presence_begin(&state,cid,epoch,pressed!=0,now);
}
API int presence_sample(int pressed, uint32_t now) { return key_presence_sample(&state,pressed!=0,now); }
API uint32_t presence_progress(uint32_t now) { return key_presence_progress(&state,now); }
API int presence_inputs(int released, int confirmed, uint32_t now) {
    return key_presence_sample_inputs(&state,released!=0,confirmed!=0,now);
}
API int presence_cancel(uint32_t cid, uint32_t epoch) { return key_presence_cancel(&state,cid,epoch); }
API int presence_consume(uint32_t cid, uint32_t epoch, uint32_t now) {
    return key_presence_consume(&state,cid,epoch,now);
}
